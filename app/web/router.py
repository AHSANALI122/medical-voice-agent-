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
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.db.base import db_session
from app.schemas.types import StrictModel
from app.security import rate_limit
from app.security.request_auth import client_ip
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
