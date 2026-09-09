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
from app.observability import stamp

HEADER_CHANNEL = "x-vb-channel"
HEADER_TIMESTAMP = "x-vb-timestamp"
HEADER_NONCE = "x-vb-nonce"
HEADER_SIGNATURE = "x-vb-signature"
HEADER_CALL_ID = "x-vb-call-id"

_UNAUTHENTICATED = "unauthenticated request"

# A platform call identifier: Vapi's call id, or whatever the web channel mints
# per connection. Bounded and drawn from a closed character set before it is
# used for anything, because it becomes a rate-limit key.
_CALL_ID_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)
MAX_CALL_ID_LENGTH = 64


def sign(
    secret: bytes, timestamp: str, nonce: str, raw_body: bytes, call_id: str = ""
) -> str:
    """Canonical form: timestamp, nonce, call id, then the raw bytes as sent.

    Signing the raw body rather than a re-serialized copy means a tampered byte
    anywhere in the payload breaks the signature, including in a field this
    version of the server does not read.

    The nonce is in the signed material because replay protection and
    idempotency would otherwise fight each other: a client retrying after a
    network timeout sends the same bytes in the same second, which without a
    nonce is byte-identical to an attacker replaying a captured request. With
    one, a retry is a new request that the idempotency layer recognizes (F15),
    while a replay reuses a spent nonce and is refused.

    The call id is in there for a different reason. It is a rate-limit key (F8),
    and an unsigned header is a key the caller picks — which is the same failure
    the X-Forwarded-For handling below exists to avoid. An abuser who can mint a
    fresh call id per request has no call budget at all. Signed, it is as
    trustworthy as the channel secret, and no more: the source-IP budget is the
    one that still binds a client that has gone hostile.
    """
    message = b".".join(
        (
            timestamp.encode("ascii"),
            nonce.encode("ascii"),
            call_id.encode("ascii"),
            raw_body,
        )
    )
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
    """Proof of a known client. Carries no authority over any record.

    `call_id` is a budget key, not an identity: two calls sharing one are the
    same platform call, which says nothing about who is speaking.
    """

    name: str
    client_ip: str
    call_id: str | None = None


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
    x_vb_call_id: str | None = Header(default=None),
) -> AuthenticatedChannel:
    if not x_vb_channel or not x_vb_timestamp or not x_vb_nonce or not x_vb_signature:
        raise _reject()

    nonce = x_vb_nonce.strip()
    if not 8 <= len(nonce) <= 64 or not nonce.isalnum():
        raise _reject()

    call_id = (x_vb_call_id or "").strip()
    if call_id and (
        len(call_id) > MAX_CALL_ID_LENGTH or set(call_id) - _CALL_ID_ALLOWED
    ):
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
    expected = sign(secret, x_vb_timestamp, nonce, raw_body, call_id)

    if not hmac.compare_digest(expected, x_vb_signature.strip()):
        raise _reject()

    # Spend the nonce only after the signature verifies, so an unauthenticated
    # caller cannot burn nonces a real client is about to use.
    if get_replay_cache().seen_before(f"{channel}:{nonce}"):
        raise _reject()

    # F11 — the channel is the first thing an event row can honestly carry, and
    # it is known only once the signature has verified. Stamping it here rather
    # than in the middleware means an unauthenticated probe's event says nothing
    # about which channel it claimed to be.
    stamp(request, channel=channel)

    return AuthenticatedChannel(
        name=channel, client_ip=client_ip(request), call_id=call_id or None
    )
