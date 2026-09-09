"""Abuse budgets (F8 — C-07, C-14, C-23, C-29, C-34).

Five budgets, one mechanism: a fixed-window counter row keyed by an HMAC of the
scope plus whatever identifies the subject.

  cancel_reference  (source IP, name asked about)  failed-reference lockout
  session_ip        source IP                      calls accepted per day
  session_call      platform call id               calls accepted per day
  booking_name      normalized patient name        soft daily booking cap
  booking_global    nothing                        hard daily booking backstop

Three properties this module exists to hold:

**The budget belongs to the caller, not to the record.** Charging the appointment
was the obvious reading of C-34 and it is wrong in the direction that matters:
anyone who knows a name and a date could burn five wrong guesses and lock a real
patient out of their own booking. Keyed on (source IP, name asked about), the
same five guesses cost the guesser their next hour and cost the patient nothing
— a second caller holding the correct reference cancels normally.

**Budgets live in the database, so a reconnect resets nothing (C-23).** Nothing
here keys on `session_id`, which is precisely the value an abuser can refresh at
will. They do reset on a redeploy, along with everything else — that is F0's
ephemeral posture, stated rather than hidden.

**The key is an HMAC.** `rate_limit_buckets` is not an encrypted table and one of
these subjects is a patient name. Hashing the tuple gives a value stable enough
to count against and useless to anyone reading the table.

One honest limit, stated rather than hidden: the per-name booking cap is the soft
layer because a name is neither secret nor verified — an abuser evades it by
saying a different name. It is friction, not a control. The global cap is the
hard backstop, because nothing a caller controls can move it.
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
SCOPE_SESSION_IP = "session_ip"
SCOPE_SESSION_CALL = "session_call"
SCOPE_BOOKING_NAME = "booking_name"
SCOPE_BOOKING_GLOBAL = "booking_global"
# F12 — room tokens minted per source address. Its own counter rather than a
# share of the call budget, so a legitimate mint-then-connect does not spend
# two of a caller's three daily calls.
SCOPE_ROOM_TOKEN = "room_token"
# F13 — not a counter at all. See `call_clock` below.
SCOPE_CALL_DURATION = "call_duration"

# The one caller-facing text for every refused budget. A caller who trips the
# global cap and a caller who has been hammering one line hear the same thing,
# so the response teaches nothing about which limit exists or where it sits.
RATE_LIMITED_TEXT = (
    "I can't take that request right now. Please try again later, "
    "or contact the clinic directly."
)


class RateLimited(Exception):
    """A budget refused. Carries the scope for the audit trail, never for the
    caller — the caller-facing text is identical for every scope.

    `first_refusal` exists so that hammering a spent budget cannot be used to
    write audit rows without limit. One row per budget per window records the
    event; the bucket's own count records how hard it was hit after that.
    """

    def __init__(self, scope: str, *, first_refusal: bool = True) -> None:
        super().__init__(f"rate limit exceeded: {scope}")
        self.scope = scope
        self.first_refusal = first_refusal


@dataclass(frozen=True)
class BudgetState:
    """`locked` reads naturally at the cancel lockout; `exceeded` is the same
    fact under the name the counting budgets use.
    """

    locked: bool
    failures: int
    locked_until: datetime | None

    @property
    def exceeded(self) -> bool:
        return self.locked

    @property
    def count(self) -> int:
        return self.failures


# --------------------------------------------------------------- primitives


def _key(scope: str, *parts: str) -> str:
    return bucket_key(scope, *parts)


def _load(db: OrmSession, scope: str, key: str) -> RateLimitBucket | None:
    return db.execute(
        select(RateLimitBucket)
        .where(RateLimitBucket.scope == scope)
        .where(RateLimitBucket.bucket_key == key)
    ).scalar_one_or_none()


def _window_for(scope: str) -> timedelta:
    settings = get_settings()
    if scope == SCOPE_CANCEL_REFERENCE:
        return timedelta(minutes=settings.reference_lock_minutes)
    return timedelta(hours=settings.abuse_window_hours)


def _limit_for(scope: str) -> int:
    settings = get_settings()
    return {
        SCOPE_CANCEL_REFERENCE: settings.max_reference_attempts,
        SCOPE_SESSION_IP: settings.max_sessions_per_ip_per_day,
        SCOPE_SESSION_CALL: settings.max_sessions_per_call_id_per_day,
        SCOPE_BOOKING_NAME: settings.max_bookings_per_name_per_day,
        SCOPE_BOOKING_GLOBAL: settings.max_bookings_per_day_global,
        SCOPE_ROOM_TOKEN: settings.max_room_tokens_per_ip_per_day,
    }[scope]


def peek(
    db: OrmSession, *, scope: str, parts: tuple[str, ...], now: datetime | None = None
) -> BudgetState:
    """Where this subject stands. Reads only; never counts."""
    now = now or datetime.now(timezone.utc)
    bucket = _load(db, scope, _key(scope, *parts))
    if bucket is None:
        return BudgetState(locked=False, failures=0, locked_until=None)

    expires = bucket.window_start_utc + _window_for(scope)
    if now >= expires:
        # The window has run out: this subject starts clean.
        return BudgetState(locked=False, failures=0, locked_until=None)

    over = bucket.count >= _limit_for(scope)
    return BudgetState(
        locked=over, failures=bucket.count, locked_until=expires if over else None
    )


def consume(
    db: OrmSession,
    *,
    scope: str,
    parts: tuple[str, ...],
    now: datetime | None = None,
    extend_window_on_limit: bool = False,
) -> BudgetState:
    """Charge one unit to this subject and report where they now stand.

    `extend_window_on_limit` restarts the clock each time an already-exhausted
    subject spends again. The cancel lockout uses it, so continued hammering
    keeps the guesser in the penalty box while a caller who has stopped guessing
    walks out of it on time. The counting budgets do not: a fixed daily window
    should expire on schedule regardless of how hard it was hit.
    """
    now = now or datetime.now(timezone.utc)
    key = _key(scope, *parts)
    bucket = _load(db, scope, key)
    window = _window_for(scope)

    if bucket is None:
        bucket = RateLimitBucket(
            scope=scope,
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

    if extend_window_on_limit and bucket.count >= _limit_for(scope):
        bucket.window_start_utc = now

    db.flush()
    return peek(db, scope=scope, parts=parts, now=now)


def reset(db: OrmSession, *, scope: str, parts: tuple[str, ...]) -> None:
    bucket = _load(db, scope, _key(scope, *parts))
    if bucket is not None:
        bucket.count = 0


def require(
    db: OrmSession, *, scope: str, parts: tuple[str, ...], now: datetime | None = None
) -> None:
    """Refuse the request if this subject has already spent its budget.

    A refusal is counted but the window is **not** extended: the penalty for
    exceeding a daily cap is the cap, not a lengthening sentence. Counting the
    refusal is what lets the caller tell a first refusal from the ten-thousandth
    and write one audit row rather than ten thousand — found by asking what an
    authenticated client that ignores a 429 costs the disk.
    """
    if not peek(db, scope=scope, parts=parts, now=now).exceeded:
        return

    after = consume(db, scope=scope, parts=parts, now=now)
    raise RateLimited(scope, first_refusal=after.count == _limit_for(scope) + 1)


# ------------------------------------------------- cancel-reference lockout


def state(
    db: OrmSession, *, client_ip: str, normalized_name: str, now: datetime | None = None
) -> BudgetState:
    return peek(
        db, scope=SCOPE_CANCEL_REFERENCE, parts=(client_ip, normalized_name), now=now
    )


def record_failure(
    db: OrmSession, *, client_ip: str, normalized_name: str, now: datetime | None = None
) -> BudgetState:
    """Charge one failed reference attempt to this caller.

    A failure while already locked restarts the hour: hammering extends the
    penalty rather than costing nothing.
    """
    return consume(
        db,
        scope=SCOPE_CANCEL_REFERENCE,
        parts=(client_ip, normalized_name),
        now=now,
        extend_window_on_limit=True,
    )


def clear(db: OrmSession, *, client_ip: str, normalized_name: str) -> None:
    """A correct reference ends the penalty. Fumbling before getting it right is
    what people do; only failure that never lands is worth charging for.
    """
    reset(db, scope=SCOPE_CANCEL_REFERENCE, parts=(client_ip, normalized_name))


# ------------------------------------------------------------ call budgets


def require_call_budget(
    db: OrmSession, *, client_ip: str, call_id: str | None, now: datetime | None = None
) -> None:
    """Both budgets are checked before either is charged, so a caller refused by
    one does not silently spend the other.
    """
    require(db, scope=SCOPE_SESSION_IP, parts=(client_ip,), now=now)
    if call_id:
        require(db, scope=SCOPE_SESSION_CALL, parts=(call_id,), now=now)


def consume_call_budget(
    db: OrmSession, *, client_ip: str, call_id: str | None, now: datetime | None = None
) -> None:
    consume(db, scope=SCOPE_SESSION_IP, parts=(client_ip,), now=now)
    if call_id:
        consume(db, scope=SCOPE_SESSION_CALL, parts=(call_id,), now=now)


# --------------------------------------------------------- booking budgets


def require_booking_budget(
    db: OrmSession, *, normalized_name: str, now: datetime | None = None
) -> None:
    """Hard backstop first, then the soft layer.

    Order matters for what a probing caller learns: once the global cap is spent
    every name is refused identically, so the per-name cap can never be used as a
    signal about somebody else's activity.
    """
    require(db, scope=SCOPE_BOOKING_GLOBAL, parts=(), now=now)
    require(db, scope=SCOPE_BOOKING_NAME, parts=(normalized_name,), now=now)


def consume_booking_budget(
    db: OrmSession, *, normalized_name: str, now: datetime | None = None
) -> None:
    """Charged only once an appointment row actually exists.

    A caller who loses the slot race pays nothing: the resource the cap protects
    is a booked slot, not an attempt.
    """
    consume(db, scope=SCOPE_BOOKING_NAME, parts=(normalized_name,), now=now)
    consume(db, scope=SCOPE_BOOKING_GLOBAL, parts=(), now=now)


# --------------------------------------------------------------------------
# F12 — room token budget
# --------------------------------------------------------------------------


def require_room_token_budget(db: OrmSession, *, client_ip: str) -> None:
    """The browser mints room tokens without a channel secret, so the source
    address is the only thing binding it. An unbudgeted mint endpoint is a free
    token generator, which is the web half of the denial-of-wallet in C-07.
    """
    require(db, scope=SCOPE_ROOM_TOKEN, parts=(client_ip,))


def consume_room_token_budget(db: OrmSession, *, client_ip: str) -> None:
    consume(db, scope=SCOPE_ROOM_TOKEN, parts=(client_ip,))


# --------------------------------------------------------------------------
# F13 — the call duration clock
# --------------------------------------------------------------------------
#
# Deliberately not a counter. Every other budget here asks "how many times?";
# this one asks "for how long?", and reusing `consume` would be wrong in a way
# that is easy to miss: `consume` restarts `window_start_utc` once a window
# lapses, which for a duration cap means a long call resets its own clock and
# runs forever.
#
# So the bucket is used as a first-seen timestamp. `count` records how many
# requests the call made, which is telemetry rather than a limit; the decision
# is made on elapsed wall time alone.
#
# It exists at all because Vapi's own `maxDurationSeconds` is a setting in
# somebody else's dashboard. A cap enforced only where it can be clicked off is
# not a cap (F13 acceptance: enforced at the platform *and* the server).


@dataclass(frozen=True)
class CallClock:
    started_at: datetime
    elapsed_seconds: float
    expired: bool


def call_clock(
    db: OrmSession, *, call_id: str, now: datetime | None = None, touch: bool = False
) -> CallClock:
    """Where a platform call stands against the duration cap.

    Reads only, unless `touch=True`. That distinction matters more than it
    looks: this runs on every authorized turn, and a version that wrote on the
    read path both double-counted and mutated a row it had no reason to touch.

    `touch=True` starts the clock if it is not already running. Only
    `create_session` touches it: a call's clock begins when the call begins, and
    a later request must never be able to restart it.
    """
    settings = get_settings()
    now = now or datetime.now(timezone.utc)
    key = _key(SCOPE_CALL_DURATION, call_id)
    bucket = _load(db, SCOPE_CALL_DURATION, key)

    if bucket is None:
        if not touch:
            # No clock yet and nothing to start one: an unknown call has run for
            # no time, which is the honest answer and refuses nobody.
            return CallClock(started_at=now, elapsed_seconds=0.0, expired=False)
        bucket = RateLimitBucket(
            scope=SCOPE_CALL_DURATION,
            bucket_key=key,
            window_start_utc=now,
            count=0,
            updated_at=now,
        )
        db.add(bucket)

    if touch:
        # `count` is telemetry here, not a limit — how many sessions this call
        # opened. The decision is made on elapsed wall time alone.
        bucket.count += 1
        bucket.updated_at = now
        db.flush()

    elapsed = (now - bucket.window_start_utc).total_seconds()
    return CallClock(
        started_at=bucket.window_start_utc,
        elapsed_seconds=elapsed,
        expired=elapsed > settings.max_call_seconds,
    )


def require_call_within_duration(
    db: OrmSession, *, call_id: str | None, now: datetime | None = None
) -> None:
    """Refuse a call that has outlived the cap.

    A call with no platform id — the tester, or a web session before a call id
    is minted — is not capped here. Nothing is lost: those channels are bounded
    by the 15-minute session TTL and by the per-IP call budget, and the cap this
    enforces exists for the one channel that costs money per minute.
    """
    if not call_id:
        return
    clock = call_clock(db, call_id=call_id, now=now)
    if clock.expired:
        raise RateLimited(SCOPE_CALL_DURATION)


def start_call_clock(
    db: OrmSession, *, call_id: str | None, now: datetime | None = None
) -> None:
    if not call_id:
        return
    call_clock(db, call_id=call_id, now=now, touch=True)
