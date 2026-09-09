"""C-31, C-34 — a 4-digit code is a weak secret, so guessing must be expensive.

10,000 combinations is nothing to a script. The lockout is what turns "a few
seconds of guessing" into "five tries an hour", and section 2 says plainly that
this makes brute force impractical rather than impossible.

The budget is charged to the caller, not to the appointment. That is a
deliberate departure from C-34 as written: a counter on the record would let
anyone who knows a name and a date lock a real patient out of their own booking,
turning the defence into the attack. The last two tests here are the ones that
would have caught that.
"""

from __future__ import annotations

from sqlalchemy import select

from app.config import get_settings
from app.security import rate_limit
from app.models import (
    ACTION_CANCEL,
    DECISION_DENIED,
    REASON_LOCKED,
    STATUS_ACTIVE,
    STATUS_CANCELLED,
    Appointment,
    AuditEvent,
    RateLimitBucket,
)

WRONG_GUESSES = ("0001", "0002", "0003", "0004", "0005")


def _cancel(api, session_id, *, name, day, reference):
    return api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": name,
            "appointment_date": day,
            "reference": reference,
        },
    )


def _burn_the_budget(api, session_id, record):
    for guess in WRONG_GUESSES:
        assert guess != record["reference"]
        assert (
            _cancel(
                api, session_id, name=record["name"], day=record["date"], reference=guess
            ).status_code
            == 403
        )


def test_the_fifth_wrong_guess_locks_the_guesser(api, session_id, booked, db):
    record = booked(name="Ahmed Khan")
    _burn_the_budget(api, session_id, record)

    # Scoped, because F8 added counting budgets that share this table. The
    # lockout is one bucket among several and must be read as such.
    bucket = (
        db.execute(
            select(RateLimitBucket).where(
                RateLimitBucket.scope == rate_limit.SCOPE_CANCEL_REFERENCE
            )
        )
        .scalars()
        .one()
    )
    assert bucket.count >= get_settings().max_reference_attempts

    # The guesser is refused even holding the correct reference, and refused
    # identically to every other failure.
    locked = _cancel(
        api, session_id, name="Ahmed Khan", day=record["date"], reference=record["reference"]
    )
    assert locked.status_code == 403
    assert (
        locked.json()
        == _cancel(
            api, session_id, name="Nobody Atall", day=record["date"], reference="0000"
        ).json()
    )

    # The appointment is untouched. A lockout protects the booking; it does not
    # damage it.
    appointment = db.execute(
        select(Appointment).where(Appointment.status == STATUS_ACTIVE)
    ).scalar_one()
    assert appointment.cancelled_at is None


def test_a_guesser_cannot_lock_the_real_patient_out(api, session_id, booked, db, other_ip_api):
    """The failure mode this design exists to avoid.

    An attacker who knows only a name and a date burns five guesses. The patient
    then calls from their own line with the correct reference and it works.
    """
    record = booked(name="Ahmed Khan")
    _burn_the_budget(api, session_id, record)

    patient_session = other_ip_api.post(
        "/tools/create_session", {"consent_given": True}
    ).json()["session_id"]

    cancelled = _cancel(
        other_ip_api,
        patient_session,
        name="Ahmed Khan",
        day=record["date"],
        reference=record["reference"],
    )
    assert cancelled.status_code == 200

    appointment = db.execute(
        select(Appointment).where(Appointment.status == STATUS_CANCELLED)
    ).scalar_one()
    assert appointment.cancelled_at is not None


def test_a_new_session_from_the_same_source_does_not_reset_the_budget(
    api, session_id, booked, db
):
    """C-23: reconnecting is the cheapest reset there is, so it must not work."""
    record = booked(name="Ahmed Khan")
    _burn_the_budget(api, session_id, record)

    fresh_session = api.post("/tools/create_session", {"consent_given": True}).json()[
        "session_id"
    ]
    still_locked = _cancel(
        api,
        fresh_session,
        name="Ahmed Khan",
        day=record["date"],
        reference=record["reference"],
    )
    assert still_locked.status_code == 403


def test_the_lockout_is_audited(api, session_id, booked, db):
    record = booked(name="Ahmed Khan")
    _burn_the_budget(api, session_id, record)
    _cancel(
        api, session_id, name="Ahmed Khan", day=record["date"], reference=record["reference"]
    )

    reasons = (
        db.execute(
            select(AuditEvent.reason)
            .where(AuditEvent.action == ACTION_CANCEL)
            .where(AuditEvent.decision == DECISION_DENIED)
        )
        .scalars()
        .all()
    )
    assert REASON_LOCKED in reasons


def test_every_attempt_writes_exactly_one_audit_row(api, session_id, booked, db):
    """C-28: allowed or denied, one row per attempt, no more and no fewer."""
    record = booked(name="Ahmed Khan")

    before = len(
        db.execute(select(AuditEvent.id).where(AuditEvent.action == ACTION_CANCEL))
        .scalars()
        .all()
    )
    _cancel(api, session_id, name="Ahmed Khan", day=record["date"], reference="0000")
    _cancel(
        api, session_id, name="Ahmed Khan", day=record["date"], reference=record["reference"]
    )
    after = len(
        db.execute(select(AuditEvent.id).where(AuditEvent.action == ACTION_CANCEL))
        .scalars()
        .all()
    )
    assert after - before == 2


def test_a_denied_attempt_leaves_no_trace_in_the_appointment_status(api, session_id, booked, db):
    record = booked(name="Ahmed Khan")
    _cancel(api, session_id, name="Ahmed Khan", day=record["date"], reference="9999")
    appointment = db.execute(
        select(Appointment).where(Appointment.status == STATUS_ACTIVE)
    ).scalar_one()
    assert appointment.cancelled_at is None


def test_the_budget_key_reveals_neither_the_name_nor_the_address(api, session_id, booked, db):
    """rate_limit_buckets is not an encrypted table, so nothing readable goes in."""
    record = booked(name="Ahmed Khan")
    _cancel(api, session_id, name="Ahmed Khan", day=record["date"], reference="0000")

    for bucket in db.execute(select(RateLimitBucket)).scalars().all():
        assert "ahmed" not in bucket.bucket_key.lower()
        assert "testclient" not in bucket.bucket_key.lower()
        assert len(bucket.bucket_key) == 64
