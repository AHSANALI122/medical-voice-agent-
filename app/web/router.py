"""The browser-facing endpoints (F12, C-27).

Two routes, and neither is a tool. `/tools/*` is the authenticated surface every
channel shares; this is the small amount of plumbing a browser needs before a
call exists at all.

`/web/room-token` is the only unauthenticated POST in the system, and it is
unauthenticated because it has to be: the browser holds no channel secret and
must not be given one (C-16). What stops it being a free token mint is the
per-address budget and the sixty-second lifetime, not a credential.

`/web/config` exists so the page has somewhere to read its settings from that is
not a build-time inlined constant. It returns no key, no secret and no provider
identifier — `scripts/check_client_bundle.py` is what keeps that true.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import Field
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.db.base import db_session
from app.schemas.types import StrictModel
from app.security import rate_limit
from app.security.request_auth import (
    AuthenticatedChannel,
    client_ip,
    require_signed_request,
)
from app.web import tokens

log = logging.getLogger("voicebook.web")

router = APIRouter(prefix="/web", tags=["web"])


class RoomTokenResult(StrictModel):
    """Everything the browser is given, and nothing else.

    No provider key, no room server credential, no account identifier. The
    browser learns a room name it cannot guess and a token it cannot forge, both
    of which stop mattering in a minute.
    """

    room: str
    token: str
    expires_in_seconds: int


class WebConfigResult(StrictModel):
    """Client settings. Every field here is safe to read in a page source."""

    consent_required: bool
    disclosure: str
    emergency_service: str
    emergency_number: str
    default_silence_ms: int
    digit_silence_ms: int


@router.post("/room-token", response_model=RoomTokenResult)
def room_token(
    request: Request,
    db: OrmSession = Depends(db_session),
) -> RoomTokenResult:
    try:
        rate_limit.require_room_token_budget(db, client_ip=client_ip(request))
    except rate_limit.RateLimited:
        # The same uniform 429 every other budget gives. A browser that learns
        # which limit it tripped learns which one to work around.
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_limit.RATE_LIMITED_TEXT,
        ) from None

    minted = tokens.mint()
    rate_limit.consume_room_token_budget(db, client_ip=client_ip(request))
    db.commit()

    # The room id is logged, the token is not. One identifies a room, the other
    # opens it.
    log.info("room_token_minted room=%s ttl=%d", minted.room, minted.ttl_seconds)

    return RoomTokenResult(
        room=minted.room,
        token=minted.token,
        expires_in_seconds=minted.ttl_seconds,
    )


@router.get("/config", response_model=WebConfigResult)
def web_config() -> WebConfigResult:
    from app.tools.router import DISCLOSURE

    settings = get_settings()
    return WebConfigResult(
        consent_required=True,
        disclosure=DISCLOSURE,
        emergency_service=settings.vb_emergency_service_name,
        emergency_number=settings.vb_emergency_number,
        default_silence_ms=settings.vad_default_silence_ms,
        digit_silence_ms=settings.vad_digit_silence_ms,
    )


# One body for every refusal, the same reasoning as the uniform cancellation
# failure (6.2) applied to a much smaller thing. Expired, tampered, wrong room
# and wrong channel are indistinguishable from outside.
ROOM_TOKEN_REFUSED = "room token refused"


class RoomTokenVerifyRequest(StrictModel):
    """What the signalling server presents on behalf of a browser."""

    token: str = Field(min_length=1, max_length=512)
    room: str = Field(min_length=1, max_length=128)


class RoomTokenVerifyResult(StrictModel):
    room: str
    expires_in_seconds: int


@router.post("/room-token/verify", response_model=RoomTokenVerifyResult)
def verify_room_token(
    payload: RoomTokenVerifyRequest,
    channel: AuthenticatedChannel = Depends(require_signed_request),
) -> RoomTokenVerifyResult:
    """Answer one question for the web signalling server: may this token open
    this room?

    It exists because the signalling server **cannot** answer it itself. The
    verifier and `VB_ROOM_TOKEN_KEY` live here, in the trusted zone, and
    `agent/` may hold an HTTP client and nothing else from this codebase (C-19).
    A signalling process that verified locally would need the room token key in
    the one process that accepts WebRTC offers from strangers — and the moment
    it holds that key it can mint tokens as well as check them. Over HTTP it can
    only ask.

    This is authorization, not validation, so it is 403 and not 422 (C-36). A
    well-formed token from a stranger is still a token this server did not mint.

    The `web` channel restriction is the point of scoping a secret per channel.
    Phone and tester have no rooms; if either of their secrets leaks, it must not
    become a key to a browser's media room.
    """
    if channel.name != "web":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=ROOM_TOKEN_REFUSED
        )

    try:
        verified = tokens.verify(payload.token, room=payload.room)
    except tokens.InvalidRoomToken:
        # Nothing about the token is logged. It is a credential, short-lived or
        # not, and a rejected one is still one somebody tried.
        log.info("room_token_refused room=%s", payload.room[:32])
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=ROOM_TOKEN_REFUSED
        ) from None

    return RoomTokenVerifyResult(
        room=verified.room, expires_in_seconds=verified.ttl_seconds
    )
