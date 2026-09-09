"""Failed-reference budget (C-34, C-23).

The budget belongs to the caller, not to the appointment.

Charging the appointment was the obvious reading of C-34 and it is wrong in a
way that only shows up from the other side: anyone who knows a name and a date
can burn five wrong guesses and lock a real patient out of their own booking.
The lockout would become the attack. Keyed on (source IP, name asked about), the
same five guesses cost the guesser their next hour and cost the patient nothing
— a second caller with the correct reference still cancels normally.

The bucket key is an HMAC of the pair, because `rate_limit_buckets` is not an
encrypted table and the name is PHI.

Budgets live in the database, so a reconnect resets nothing (C-23). They do
reset on a redeploy, along with everything else — that is F0's ephemeral
posture, stated rather than hidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.models import RateLimitBucket
from app.security.crypto import bucket_key

SCOPE_CANCEL_REFERENCE = "cancel_reference"


@dataclass(frozen=True)
class BudgetState:
    locked: bool
    failures: int
    locked_until: datetime | None


def _key(client_ip: str, normalized_name: str) -> str:
    return bucket_key(SCOPE_CANCEL_REFERENCE, client_ip, normalized_name)


def _load(db: OrmSession, key: str) -> RateLimitBucket | None:
    return db.execute(
        select(RateLimitBucket)
        .where(RateLimitBucket.scope == SCOPE_CANCEL_REFERENCE)
        .where(RateLimitBucket.bucket_key == key)
    ).scalar_one_or_none()


def state(
    db: OrmSession, *, client_ip: str, normalized_name: str, now: datetime | None = None
) -> BudgetState:
    """Where this caller stands. Reads only; never counts."""
    settings = get_settings()
    now = now or datetime.now(timezone.utc)
    bucket = _load(db, _key(client_ip, normalized_name))
    if bucket is None:
        return BudgetState(locked=False, failures=0, locked_until=None)

    expires = bucket.window_start_utc + timedelta(minutes=settings.reference_lock_minutes)
    if now >= expires:
        # The window has run out: this caller starts clean.
        return BudgetState(locked=False, failures=0, locked_until=None)

    locked = bucket.count >= settings.max_reference_attempts
    return BudgetState(
        locked=locked, failures=bucket.count, locked_until=expires if locked else None
    )


def record_failure(
    db: OrmSession, *, client_ip: str, normalized_name: str, now: datetime | None = None
) -> BudgetState:
    """Charge one failed reference attempt to this caller.

    A failure while already locked restarts the hour. Continued hammering keeps
    the guesser in the penalty box; a caller who has stopped guessing walks out
    of it on time.
    """
    settings = get_settings()
    now = now or datetime.now(timezone.utc)
    key = _key(client_ip, normalized_name)
    bucket = _load(db, key)
    window = timedelta(minutes=settings.reference_lock_minutes)

    if bucket is None:
        bucket = RateLimitBucket(
            scope=SCOPE_CANCEL_REFERENCE,
            bucket_key=key,
            window_start_utc=now,
            count=0,
            updated_at=now,
        )
        db.add(bucket)
    elif now >= bucket.window_start_utc + window:
        bucket.window_start_utc = now
        bucket.count = 0

    bucket.count += 1
    bucket.updated_at = now

    if bucket.count >= settings.max_reference_attempts:
        bucket.window_start_utc = now

    db.flush()
    return state(db, client_ip=client_ip, normalized_name=normalized_name, now=now)


def clear(
    db: OrmSession, *, client_ip: str, normalized_name: str
) -> None:
    """A correct reference ends the penalty. Fumbling before getting it right is
    what people do; only failure that never lands is worth charging for.
    """
    bucket = _load(db, _key(client_ip, normalized_name))
    if bucket is not None:
        bucket.count = 0
