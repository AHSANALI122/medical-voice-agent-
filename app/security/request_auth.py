"""Request authentication (F4, C-03, C-19).

Every /tools/* call carries a channel name, a timestamp, and an HMAC-SHA256 over
timestamp + raw body, computed with that channel's own shared secret. The agent
package authenticates exactly like any other external caller, because it is one.

This layer answers "is this a real client on a known channel?" and returns 401
when it is not. It never answers "may this caller cancel that appointment?" —
that is authorization, it happens later, and it returns 403 (C-36).
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request, status

from app.config import CHANNELS, get_settings

HEADER_CHANNEL = "x-vb-channel"
HEADER_TIMESTAMP = "x-vb-timestamp"
HEADER_NONCE = "x-vb-nonce"
HEADER_SIGNATURE = "x-vb-signature"

_UNAUTHENTICATED = "unauthenticated request"


def sign(secret: bytes, timestamp: str, nonce: str, raw_body: bytes) -> str:
    """Canonical form: timestamp, nonce, then the raw bytes as sent.

    Signing the raw body rather than a re-serialized copy means a tampered byte
    anywhere in the payload breaks the signature, including in a field this
    version of the server does not read.

    The nonce is in the signed material because replay protection and
    idempotency would otherwise fight each other: a client retrying after a
    network timeout sends the same bytes in the same second, which without a
    nonce is byte-identical to an attacker replaying a captured request. With
    one, a retry is a new request that the idempotency layer recognizes (F15),
    while a replay reuses a spent nonce and is refused.
    """
    message = timestamp.encode("ascii") + b"." + nonce.encode("ascii") + b"." + raw_body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


class ReplayCache:
    """Nonces already spent, within the freshness window.

    Bounded by the window, not by a count: entries older than the window can
    never be replayed successfully anyway, because the timestamp check rejects
    them first.
    """

    def __init__(self, window_seconds: int) -> None:
        self._window = window_seconds
        self._seen: dict[str, float] = {}

    def seen_before(self, nonce: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        self._prune(now)
        if nonce in self._seen:
            return True
        self._seen[nonce] = now
        return False

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        stale = [nonce for nonce, seen_at in self._seen.items() if seen_at < cutoff]
        for nonce in stale:
            del self._seen[nonce]

    def clear(self) -> None:
        self._seen.clear()


_replay_cache: ReplayCache | None = None


def get_replay_cache() -> ReplayCache:
    global _replay_cache
    if _replay_cache is None:
        _replay_cache = ReplayCache(get_settings().signature_max_age_seconds)
    return _replay_cache


@dataclass(frozen=True)
class AuthenticatedChannel:
    """Proof of a known client. Carries no authority over any record."""

    name: str
    client_ip: str


UNKNOWN_IP = "unknown"


def client_ip(request: Request) -> str:
    """The address abuse budgets are charged to (C-34).

    X-Forwarded-For is a list a client can write into, so it is read only as far
    back as the number of proxies actually in front of this service. With none
    configured, the peer address is the only thing believed. Getting this wrong
    is how a rate limit becomes decorative: an attacker who can pick their own
    key has no budget at all.
    """
    hops = get_settings().vb_trusted_proxy_hops
    if hops > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    if request.client is not None and request.client.host:
        return request.client.host
    return UNKNOWN_IP


def _reject() -> HTTPException:
    # One message for every authentication failure: a tampered body, a stale
    # timestamp and an unknown channel are indistinguishable from outside.
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_UNAUTHENTICATED)


async def require_signed_request(
    request: Request,
    x_vb_channel: str | None = Header(default=None),
    x_vb_timestamp: str | None = Header(default=None),
    x_vb_nonce: str | None = Header(default=None),
    x_vb_signature: str | None = Header(default=None),
) -> AuthenticatedChannel:
    if not x_vb_channel or not x_vb_timestamp or not x_vb_nonce or not x_vb_signature:
        raise _reject()

    nonce = x_vb_nonce.strip()
    if not 8 <= len(nonce) <= 64 or not nonce.isalnum():
        raise _reject()

    channel = x_vb_channel.strip().lower()
    if channel not in CHANNELS:
        raise _reject()

    settings = get_settings()
    try:
        sent_at = int(x_vb_timestamp)
    except ValueError:
        raise _reject() from None

    if abs(time.time() - sent_at) > settings.signature_max_age_seconds:
        raise _reject()

    secret = settings.channel_secret(channel)
    if secret is None:
        raise _reject()

    raw_body = await request.body()
    expected = sign(secret, x_vb_timestamp, nonce, raw_body)

    if not hmac.compare_digest(expected, x_vb_signature.strip()):
        raise _reject()

    # Spend the nonce only after the signature verifies, so an unauthenticated
    # caller cannot burn nonces a real client is about to use.
    if get_replay_cache().seen_before(f"{channel}:{nonce}"):
        raise _reject()

    return AuthenticatedChannel(name=channel, client_ip=client_ip(request))
