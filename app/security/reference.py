"""Booking reference: issue and match (F5, section 5).

This is the authority spine. Everything mutating in the cancel path passes
through match_cancellation_candidate, and nothing else in the codebase decides
whether a caller may cancel.

Three properties this file exists to hold:

1. The reference is generated with `secrets`, never sequential, and is stored
   only as an HMAC (5.1).
2. Every failure is one indistinguishable outcome to the caller (C-32). Wrong
   name, wrong date, wrong reference, no such record, ambiguity and lockout all
   return the same MatchOutcome shape and the same caller-facing text.
3. The no-match path performs the same HMAC work as the match path, so response
   timing does not leak whether a named person has an appointment.

The brute-force budget lives in app.security.rate_limit and is charged to the
caller, never to the appointment — see that module for why.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.models import (
    REASON_ALREADY_CANCELLED,
    REASON_AMBIGUOUS,
    REASON_LOCKED,
    REASON_MATCH,
    REASON_NO_MATCH,
    STATUS_ACTIVE,
    Appointment,
    Patient,
)
from app.security import rate_limit
from app.security.crypto import reference_hmac

REFERENCE_LENGTH = 4

# The single caller-facing failure string (6.2). Every denial uses it verbatim.
UNIFORM_FAILURE_TEXT = (
    "I wasn't able to match that. Please check your details and try again, "
    "or contact the clinic directly."
)

# Used to burn the same HMAC work on the paths that never reach a comparison.
_TIMING_DUMMY = "0000"


class MatchResult(Enum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    LOCKED = "locked"


@dataclass(frozen=True)
class MatchOutcome:
    """What the server learned. Only `result` and `appointment_id` ever reach a
    decision; `reason` is for the audit row and never for the caller.
    """

    result: MatchResult
    appointment_id: int | None
    reason: str

    @property
    def allowed(self) -> bool:
        return self.result is MatchResult.MATCHED


def generate_reference() -> str:
    """A 4-digit code from a CSPRNG. Never sequential, never derived from a
    counter, a timestamp, or a patient attribute.
    """
    return f"{secrets.randbelow(10**REFERENCE_LENGTH):0{REFERENCE_LENGTH}d}"


def issue_reference(db: OrmSession, *, max_attempts: int = 12) -> tuple[str, bytes, str]:
    """Draw a reference that is unused among active appointments.

    Returns (plaintext, digest, key_id). The plaintext is handed to the caller
    once, at booking, and is never persisted.
    """
    for _ in range(max_attempts):
        candidate = generate_reference()
        digest, key_id = reference_hmac(candidate)
        clash = db.execute(
            select(Appointment.id)
            .where(Appointment.reference_hmac == digest)
            .where(Appointment.status == STATUS_ACTIVE)
            .limit(1)
        ).first()
        if clash is None:
            return candidate, digest, key_id
    # 10,000 codes and a demo-sized book of active appointments: exhausting this
    # means something is badly wrong, and inventing a colliding reference would
    # be worse than refusing.
    raise RuntimeError("could not issue a unique booking reference")


def _local_day_bounds(day, tz) -> tuple[datetime, datetime]:
    """Half-open [start, end) UTC bounds for one clinic-local calendar date."""
    start_local = datetime(day.year, day.month, day.day, tzinfo=tz)
    end_local = start_local + timedelta(days=1)
    return (
        start_local.astimezone(timezone.utc),
        end_local.astimezone(timezone.utc),
    )


def match_cancellation_candidate(
    db: OrmSession,
    *,
    normalized_name: str,
    appointment_date,
    reference: str,
    client_ip: str,
    now: datetime | None = None,
) -> MatchOutcome:
    """The one server-side authority check (5.2).

    All three fields are matched in a single parameterized query. The caller
    cannot learn which one failed, because there is only one failure.
    """
    settings = get_settings()
    now = now or datetime.now(timezone.utc)

    budget = rate_limit.state(
        db, client_ip=client_ip, normalized_name=normalized_name, now=now
    )
    if budget.locked:
        # Same HMAC work as every other path, and one more failure charged, so
        # that hammering a locked budget extends it rather than costing nothing.
        reference_hmac(_TIMING_DUMMY)
        rate_limit.record_failure(
            db, client_ip=client_ip, normalized_name=normalized_name, now=now
        )
        return MatchOutcome(MatchResult.LOCKED, None, REASON_LOCKED)

    tz = settings.clinic_tz
    day_start, day_end = _local_day_bounds(appointment_date, tz)
    digest, _key_id = reference_hmac(reference)

    rows = (
        db.execute(
            select(Appointment)
            .join(Patient, Patient.id == Appointment.patient_id)
            .where(Patient.name_normalized == normalized_name)
            .where(Appointment.slot_start_utc >= day_start)
            .where(Appointment.slot_start_utc < day_end)
            .where(Appointment.reference_hmac == digest)
            .where(Appointment.status == STATUS_ACTIVE)
        )
        .scalars()
        .all()
    )

    if not rows:
        # Same work as the match path, so "no such name" and "wrong reference"
        # cost the same wall clock (C-32 acceptance: under 20ms apart).
        reference_hmac(_TIMING_DUMMY)
        rate_limit.record_failure(
            db, client_ip=client_ip, normalized_name=normalized_name, now=now
        )
        return MatchOutcome(MatchResult.NO_MATCH, None, REASON_NO_MATCH)

    if len(rows) > 1:
        # Cannot happen while the partial unique index on reference_hmac holds,
        # and is still handled: guessing between two patients is the worst
        # possible outcome, and naming them aloud would leak both (C-33).
        return MatchOutcome(MatchResult.AMBIGUOUS, None, REASON_AMBIGUOUS)

    rate_limit.clear(db, client_ip=client_ip, normalized_name=normalized_name)
    return MatchOutcome(MatchResult.MATCHED, rows[0].id, REASON_MATCH)


def resolve_ambiguity(candidate_ids: list[int]) -> MatchOutcome:
    """Pure branch used by the resolver and exercised directly by tests, since
    the database index makes the multi-row case unreachable through SQL.
    """
    if not candidate_ids:
        return MatchOutcome(MatchResult.NO_MATCH, None, REASON_NO_MATCH)
    if len(candidate_ids) > 1:
        return MatchOutcome(MatchResult.AMBIGUOUS, None, REASON_AMBIGUOUS)
    return MatchOutcome(MatchResult.MATCHED, candidate_ids[0], REASON_MATCH)


__all__ = [
    "MatchOutcome",
    "MatchResult",
    "REASON_ALREADY_CANCELLED",
    "REFERENCE_LENGTH",
    "UNIFORM_FAILURE_TEXT",
    "generate_reference",
    "issue_reference",
    "match_cancellation_candidate",
    "resolve_ambiguity",
]
