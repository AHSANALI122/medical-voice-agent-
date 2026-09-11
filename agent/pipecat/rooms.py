"""Asking the API whether a room token is good (F12 — C-19, C-30).

The browser arrives at the signalling server holding a room id and a token. One
of those is a credential, and the thing that can check it lives on the other
side of the boundary: `VB_ROOM_TOKEN_KEY` and the verifier are in `app/`, and
`agent/` may hold an HTTP client and nothing else from this codebase.

That constraint is worth more than it costs. The signalling server is the
process that accepts WebRTC offers from strangers. A verifier in *that* process
needs the room token key, and a process holding the room token key can mint
tokens as well as check them — a process that can mint its own entry tickets has
no ticket check. Over HTTP it can only ask, and the answer comes from a process
no stranger can reach.

The signing code is written out via `agent.client`, the same published canonical
form every external caller computes. This is a client of a documented endpoint,
not a tool call: `/web/room-token/verify` is web plumbing and is deliberately
**not** in `agent.client.TOOLS`, because that set is the surface a compromised
model may reach and a model has no business verifying anybody's room token.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass

import httpx

from agent.client import (
    DEFAULT_BASE_URL,
    HEADER_CHANNEL,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    channel_secret,
    sign,
)

log = logging.getLogger("voicebook.agent.rooms")

VERIFY_PATH = "/web/room-token/verify"
DEFAULT_TIMEOUT_SECONDS = 4.0

# Mirrors the server's own bounds. Refusing an oversized value here spends no
# request on something the API is going to reject anyway, and keeps a hostile
# poster from making this process build a large body at all.
MAX_TOKEN_LENGTH = 512
MAX_ROOM_LENGTH = 128


@dataclass(frozen=True)
class RoomCheck:
    """The answer, and whether it is an answer at all.

    `reachable` is separate from `allowed` because the two failures deserve
    different words to the user — "that link has expired" against "the booking
    system is unavailable" — while deserving exactly the same action, which is
    to refuse the connection. C-30: a provider or network failure is an ordinary
    outcome with defined behaviour, and the defined behaviour here is to fail
    closed.
    """

    allowed: bool
    reachable: bool
    room: str
    expires_in_seconds: int = 0


def _refused(room: str, *, reachable: bool) -> RoomCheck:
    return RoomCheck(allowed=False, reachable=reachable, room=room)


def verify_room_token(
    *,
    token: str,
    room: str,
    base_url: str = DEFAULT_BASE_URL,
    channel: str = "web",
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    http: httpx.Client | None = None,
) -> RoomCheck:
    """Ask the API. Never decides anything locally except that a malformed
    request is not worth sending.
    """
    if not token or not room:
        return _refused(room, reachable=True)
    if len(token) > MAX_TOKEN_LENGTH or len(room) > MAX_ROOM_LENGTH:
        return _refused(room, reachable=True)

    body = json.dumps({"token": token, "room": room}).encode()
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    headers = {
        "content-type": "application/json",
        HEADER_CHANNEL: channel,
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: sign(channel_secret(channel), timestamp, nonce, body, ""),
    }

    client = http or httpx.Client(base_url=base_url, timeout=timeout_seconds)
    try:
        response = client.post(VERIFY_PATH, content=body, headers=headers)
    except httpx.HTTPError as exc:
        # Fail closed. An unreachable API is not permission.
        log.warning("room_token_verify_unreachable error=%s", exc.__class__.__name__)
        return _refused(room, reachable=False)
    finally:
        if http is None:
            client.close()

    if response.status_code != 200:
        # 401, 403, 422, 429 and 500 all mean the same thing to this caller: no.
        # Which one it was is a server-side fact, and the log keeps it there.
        log.info("room_token_verify_refused status=%d", response.status_code)
        return _refused(room, reachable=True)

    try:
        payload = response.json()
        return RoomCheck(
            allowed=True,
            reachable=True,
            room=str(payload["room"]),
            expires_in_seconds=int(payload["expires_in_seconds"]),
        )
    except (ValueError, KeyError, TypeError):
        return _refused(room, reachable=True)


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_ROOM_LENGTH",
    "MAX_TOKEN_LENGTH",
    "RoomCheck",
    "VERIFY_PATH",
    "verify_room_token",
]
