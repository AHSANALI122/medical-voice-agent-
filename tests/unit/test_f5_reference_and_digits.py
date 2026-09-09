"""F5 — reference issue, match, digit capture. The authority spine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.config import get_settings
from app.models import STATUS_ACTIVE, Appointment, Doctor, Patient
from app.security.crypto import reference_hmac
from app.security.normalize import normalize_name
from app.security import rate_limit
from app.security.reference import (
    MatchResult,
    generate_reference,
    issue_reference,
    match_cancellation_candidate,
    resolve_ambiguity,
)
from app.services.digits import (
    MAX_RETRIES,
    append_fragment,
    clear_buffer,
    extract_digits,
    retries_exhausted,
)


CALLER_IP = "203.0.113.7"
OTHER_IP = "198.51.100.4"


def _make_appointment(db, *, name: str, reference: str, day_offset: int = 2, doctor_index: int = 0):
    doctors = db.execute(select(Doctor)).scalars().all()
    doctor = doctors[doctor_index]
    tz = get_settings().clinic_tz
    local = (datetime.now(timezone.utc).astimezone(tz) + timedelta(days=day_offset)).replace(
        hour=10, minute=0, second=0, microsecond=0
    )
    start = local.astimezone(timezone.utc)

    digest, key_id = reference_hmac(reference)
    patient = Patient(
        name_enc=b"ciphertext",
        name_nonce=b"n" * 12,
        key_id=key_id,
        name_normalized=normalize_name(name),
    )
    db.add(patient)
    db.flush()
    appointment = Appointment(
        doctor_id=doctor.id,
        patient_id=patient.id,
        slot_start_utc=start,
        slot_end_utc=start + timedelta(minutes=30),
        status=STATUS_ACTIVE,
        reference_hmac=digest,
        reference_key_id=key_id,
    )
    db.add(appointment)
    db.commit()
    return appointment, local.date()


def test_reference_is_four_digits_and_not_sequential():
    drawn = [generate_reference() for _ in range(200)]
    assert all(len(r) == 4 and r.isdigit() for r in drawn)
    # A counter would produce a strictly increasing run; a CSPRNG does not.
    assert any(int(b) <= int(a) for a, b in zip(drawn, drawn[1:]))
    assert len(set(drawn)) > 100


def test_issue_reference_avoids_active_collisions(db):
    reference, digest, _ = issue_reference(db)
    _make_appointment(db, name="Collision Test", reference=reference)
    second, second_digest, _ = issue_reference(db)
    assert second != reference
    assert second_digest != digest


def test_correct_name_date_and_reference_matches(db):
    appointment, day = _make_appointment(db, name="Ahmed Khan", reference="4729")
    outcome = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="4729",
        client_ip=CALLER_IP,
    )
    assert outcome.result is MatchResult.MATCHED
    assert outcome.appointment_id == appointment.id


def test_wrong_reference_fails_with_the_same_outcome_as_no_such_name(db):
    _, day = _make_appointment(db, name="Ahmed Khan", reference="4729")

    wrong_reference = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="0000",
        client_ip=CALLER_IP,
    )
    no_such_name = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Nobody Atall"),
        appointment_date=day,
        reference="4729",
        client_ip=CALLER_IP,
    )

    assert wrong_reference.result is no_such_name.result is MatchResult.NO_MATCH
    assert wrong_reference.appointment_id is no_such_name.appointment_id is None
    assert wrong_reference.reason == no_such_name.reason


def test_wrong_date_fails(db):
    _, day = _make_appointment(db, name="Ahmed Khan", reference="4729")
    outcome = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day + timedelta(days=1),
        reference="4729",
        client_ip=CALLER_IP,
    )
    assert outcome.result is MatchResult.NO_MATCH


def test_five_failed_attempts_lock_the_caller_not_the_appointment(db):
    """C-34, revised: the budget belongs to whoever is guessing.

    Charging the appointment would hand any stranger who knows a name and a date
    a one-hour denial of service against a real patient. Charging the pair
    (source IP, name asked about) costs the guesser and nobody else.
    """
    appointment, day = _make_appointment(db, name="Ahmed Khan", reference="4729")
    settings = get_settings()

    for _ in range(settings.max_reference_attempts):
        match_cancellation_candidate(
            db,
            normalized_name=normalize_name("Ahmed Khan"),
            appointment_date=day,
            reference="0000",
            client_ip=CALLER_IP,
        )
    db.commit()

    budget = rate_limit.state(
        db, client_ip=CALLER_IP, normalized_name=normalize_name("Ahmed Khan")
    )
    assert budget.locked

    # The guesser is refused even with the correct reference.
    locked = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="4729",
        client_ip=CALLER_IP,
    )
    assert locked.result is MatchResult.LOCKED
    assert not locked.allowed

    # The appointment itself carries no lock, and the real patient calling from
    # anywhere else cancels normally. This is the whole point of the change.
    assert not hasattr(appointment, "locked_until_utc")
    from_elsewhere = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="4729",
        client_ip=OTHER_IP,
    )
    assert from_elsewhere.result is MatchResult.MATCHED
    assert from_elsewhere.appointment_id == appointment.id


def test_the_lock_expires_rather_than_bricking_the_caller(db):
    _, day = _make_appointment(db, name="Ahmed Khan", reference="4729")
    settings = get_settings()

    for _ in range(settings.max_reference_attempts):
        match_cancellation_candidate(
            db,
            normalized_name=normalize_name("Ahmed Khan"),
            appointment_date=day,
            reference="0000",
            client_ip=CALLER_IP,
        )
    db.commit()

    later = datetime.now(timezone.utc) + timedelta(
        minutes=settings.reference_lock_minutes + 1
    )
    assert (
        match_cancellation_candidate(
            db,
            normalized_name=normalize_name("Ahmed Khan"),
            appointment_date=day,
            reference="4729",
            client_ip=CALLER_IP,
            now=later,
        ).result
        is MatchResult.MATCHED
    )


def test_a_correct_reference_clears_the_callers_failures(db):
    """People fumble a spoken code. Only failure that never lands is charged."""
    _, day = _make_appointment(db, name="Ahmed Khan", reference="4729")

    for _ in range(3):
        match_cancellation_candidate(
            db,
            normalized_name=normalize_name("Ahmed Khan"),
            appointment_date=day,
            reference="0000",
            client_ip=CALLER_IP,
        )
    match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="4729",
        client_ip=CALLER_IP,
    )
    db.commit()

    budget = rate_limit.state(
        db, client_ip=CALLER_IP, normalized_name=normalize_name("Ahmed Khan")
    )
    assert budget.failures == 0
    assert not budget.locked


def test_a_locked_budget_covers_only_the_name_that_was_guessed_at(db):
    """Budgets are per (caller, name), so locking one probe does not lock the
    caller out of every other name they might legitimately ask about.
    """
    _, day = _make_appointment(db, name="Ahmed Khan", reference="4729")
    _make_appointment(db, name="Sana Tariq", reference="1357", doctor_index=1)
    settings = get_settings()

    for _ in range(settings.max_reference_attempts):
        match_cancellation_candidate(
            db,
            normalized_name=normalize_name("Ahmed Khan"),
            appointment_date=day,
            reference="0000",
            client_ip=CALLER_IP,
        )
    db.commit()

    other_name = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Sana Tariq"),
        appointment_date=day,
        reference="1357",
        client_ip=CALLER_IP,
    )
    assert other_name.result is MatchResult.MATCHED


def test_the_bucket_stores_no_plaintext_name(db):
    from sqlalchemy import select

    from app.models import RateLimitBucket

    _, day = _make_appointment(db, name="Ahmed Khan", reference="4729")
    match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="0000",
        client_ip=CALLER_IP,
    )
    db.commit()

    buckets = db.execute(select(RateLimitBucket)).scalars().all()
    assert buckets
    for bucket in buckets:
        assert "ahmed" not in bucket.bucket_key.lower()
        assert CALLER_IP not in bucket.bucket_key


def test_two_identically_named_patients_resolve_by_reference(db):
    """C-33: the reference disambiguates two Ahmed Khans on the same day."""
    first, day = _make_appointment(db, name="Ahmed Khan", reference="1111", doctor_index=0)
    second, _ = _make_appointment(db, name="Ahmed Khan", reference="2222", doctor_index=1)

    a = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="1111",
        client_ip=CALLER_IP,
    )
    b = match_cancellation_candidate(
        db,
        normalized_name=normalize_name("Ahmed Khan"),
        appointment_date=day,
        reference="2222",
        client_ip=CALLER_IP,
    )
    assert a.appointment_id == first.id
    assert b.appointment_id == second.id


def test_a_genuinely_ambiguous_match_hands_off_and_names_nobody():
    """If the reference collides too, refuse. Never guess, never enumerate.

    Driven through the resolver directly because the partial unique index makes
    two active rows with one reference unreachable through SQL — which is the
    first line of defence, not a reason to leave the branch untested.
    """
    outcome = resolve_ambiguity([11, 22])
    assert outcome.result is MatchResult.AMBIGUOUS
    assert outcome.appointment_id is None
    assert not outcome.allowed


def test_digit_buffer_survives_a_mid_code_vad_cut():
    """C-18: the caller says '4-7', the turn is cut, they say '2-9'."""
    state = append_fragment("", "4 7")
    assert state.digits == "47"
    assert not state.ready
    assert state.readback is None

    state = append_fragment(state.digits, "2 9")
    assert state.digits == "4729"
    assert state.ready
    assert state.readback == "4-7-2-9"


def test_digit_buffer_accepts_spoken_words_and_ignores_filler():
    assert extract_digits("four seven") == "47"
    assert extract_digits("um, two... nine") == "29"
    assert append_fragment("", "it's four seven two nine").digits == "4729"


def test_overflow_clears_rather_than_truncating():
    state = append_fragment("4729", "5")
    assert state.overflowed
    assert state.digits == ""
    assert state.retries == 1


def test_two_retries_then_handoff():
    retries = 0
    for _ in range(MAX_RETRIES):
        retries = clear_buffer(retries).retries
        assert not retries_exhausted(retries)
    retries = clear_buffer(retries).retries
    assert retries_exhausted(retries)
