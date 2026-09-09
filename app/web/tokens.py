"""Room tokens for the browser (F12, C-19, C-27).

The browser is the one caller in this system that holds no channel secret, and
it must not. Anything shipped to a browser is public — a "secret" in a client
bundle is a secret in a public repository with extra steps (C-16). So the
browser gets no credential that authenticates it as a channel; it gets a token
that authorizes **one browser to join one room for one minute**, and nothing
else.

The shape of the containment is the lifetime, not the secrecy. A room token that
leaks is worth sixty seconds of access to a room whose only occupant is the
person it was minted for. A channel secret that leaks is worth every appointment
in the database, which is exactly why the browser never sees one.

What a room token is not: it is not a session, it does not name a patient, and
it grants no authority over any record. Every mutating decision still runs
server-side against a reference (5.2). This is a door key for a media room, and
the room contains a microphone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from app.config import get_settings

TOKEN_VERSION = "v1"
_DOMAIN = b"voicebook:room-token:v1|"

ROOM_ID_BYTES = 16


class InvalidRoomToken(Exception):
    """One exception for every rejection.

    Expired, tampered, wrong room, malformed: the holder of a bad token learns
    only that it is bad. The same reasoning as the uniform cancellation failure
    (6.2), applied to a much smaller thing.
    """


@dataclass(frozen=True)
class RoomToken:
    room: str
    expires_at: int
    token: str

    @property
    def ttl_seconds(self) -> int:
        return max(0, self.expires_at - int(time.time()))


def new_room_id() -> str:
    """Unguessable, so a room cannot be joined by enumerating names."""
    return secrets.token_urlsafe(ROOM_ID_BYTES)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(payload: bytes) -> str:
    key = get_settings().room_token_key
    return _b64(hmac.new(key, _DOMAIN + payload, hashlib.sha256).digest())


def mint(room: str | None = None, *, now: int | None = None) -> RoomToken:
    """Mint a token for one room, good for `room_token_ttl_seconds`."""
    settings = get_settings()
    now = now if now is not None else int(time.time())
    room = room or new_room_id()
    expires_at = now + settings.room_token_ttl_seconds

    payload = json.dumps(
        {"v": TOKEN_VERSION, "room": room, "exp": expires_at},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    token = f"{_b64(payload)}.{_sign(payload)}"
    return RoomToken(room=room, expires_at=expires_at, token=token)


def verify(token: str, *, room: str | None = None, now: int | None = None) -> RoomToken:
    """Check a token, optionally binding it to the room being joined.

    `room` is the whole point of "room-scoped". Verifying the signature alone
    would accept a valid token for room A as entry to room B, which is a token
    that authorizes joining any room — a different and much larger thing than
    the one this mints.
    """
    now = now if now is not None else int(time.time())
    try:
        encoded, signature = token.split(".", 1)
        payload = _unb64(encoded)
    except Exception:
        raise InvalidRoomToken() from None

    # Constant-time, and before the payload is parsed: an attacker must not be
    # able to reach the JSON decoder with an unsigned blob.
    if not hmac.compare_digest(_sign(payload), signature):
        raise InvalidRoomToken()

    try:
        claims = json.loads(payload)
        version = claims["v"]
        claimed_room = claims["room"]
        expires_at = int(claims["exp"])
    except Exception:
        raise InvalidRoomToken() from None

    if version != TOKEN_VERSION:
        raise InvalidRoomToken()
    if now >= expires_at:
        raise InvalidRoomToken()
    if room is not None and not hmac.compare_digest(str(claimed_room), room):
        raise InvalidRoomToken()

    return RoomToken(room=str(claimed_room), expires_at=expires_at, token=token)


__all__ = [
    "InvalidRoomToken",
    "ROOM_ID_BYTES",
    "RoomToken",
    "TOKEN_VERSION",
    "mint",
    "new_room_id",
    "verify",
]
