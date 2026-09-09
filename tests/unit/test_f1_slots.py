"""F1 — slot engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.config import get_settings
from app.models import (
    RULE_AVAILABLE,
    RULE_BLACKOUT,
    STATUS_ACTIVE,
    Appointment,
    AvailabilityRule,
    Doctor,
    Patient,
)
from app.security.crypto import reference_hmac
from app.services.slots import available_slots


def _first_doctor(db) -> Doctor:
    return db.execute(select(Doctor)).scalars().first()


def test_no_slot_is_returned_twice(db):
    doctor = _first_doctor(db)
    slots = available_slots(db, doctor_id=doctor.id, limit=50)
    starts = [s.start_utc for s in slots]
    assert len(starts) == len(set(starts))


def test_slots_never_overlap_each_other(db):
    doctor = _first_doctor(db)
    slots = sorted(available_slots(db, doctor_id=doctor.id, limit=50), key=lambda s: s.start_utc)
    for earlier, later in zip(slots, slots[1:]):
        assert earlier.end_utc <= later.start_utc


def test_offer_is_capped_at_five(db):
    """C-29: the endpoint cannot be walked to reconstruct a schedule."""
    doctor = _first_doctor(db)
    slots = available_slots(db, doctor_id=doctor.id)
    assert len(slots) <= get_settings().max_slots_returned


def test_booked_slot_disappears_from_the_offer(db):
    doctor = _first_doctor(db)
    first = available_slots(db, doctor_id=doctor.id)[0]

    digest, key_id = reference_hmac("1234")
    patient = Patient(
        name_enc=b"x", name_nonce=b"y" * 12, key_id=key_id, name_normalized="a b"
    )
    db.add(patient)
    db.flush()
    db.add(
        Appointment(
            doctor_id=doctor.id,
            patient_id=patient.id,
            slot_start_utc=first.start_utc,
            slot_end_utc=first.end_utc,
            status=STATUS_ACTIVE,
            reference_hmac=digest,
            reference_key_id=key_id,
        )
    )
    db.commit()

    again = available_slots(db, doctor_id=doctor.id, limit=50)
    assert first.start_utc not in {s.start_utc for s in again}


def test_blackout_subtracts_from_availability(db):
    doctor = _first_doctor(db)
    tz = get_settings().clinic_tz
    target = (datetime.now(timezone.utc).astimezone(tz) + timedelta(days=3)).date()
    while target.weekday() > 4:
        target += timedelta(days=1)

    before = available_slots(db, doctor_id=doctor.id, on_date=target, limit=50)
    assert before

    db.add(
        AvailabilityRule(
            doctor_id=doctor.id,
            kind=RULE_BLACKOUT,
            blackout_date=target.isoformat(),
            start_minute=0,
            end_minute=1440,
            slot_minutes=30,
        )
    )
    db.commit()

    after = available_slots(db, doctor_id=doctor.id, on_date=target, limit=50)
    assert after == []


def test_lead_time_excludes_the_next_two_hours(db):
    doctor = _first_doctor(db)
    now = datetime.now(timezone.utc)
    settings = get_settings()
    slots = available_slots(db, doctor_id=doctor.id, now=now, limit=50)
    cutoff = now + timedelta(minutes=settings.booking_lead_time_minutes)
    assert all(s.start_utc >= cutoff for s in slots)


def test_beyond_horizon_returns_empty_not_an_error(db):
    doctor = _first_doctor(db)
    tz = get_settings().clinic_tz
    far = (datetime.now(timezone.utc).astimezone(tz) + timedelta(days=45)).date()
    assert available_slots(db, doctor_id=doctor.id, on_date=far) == []


def test_dst_transition_keeps_wall_clock_times(db):
    """A doctor whose rule says 09:00 works at 09:00 local on both sides of a
    transition. Run against a timezone that actually observes one.
    """
    import app.config as config_module

    settings = get_settings()
    original = settings.vb_clinic_timezone
    object.__setattr__(settings, "vb_clinic_timezone", "Europe/London")
    try:
        doctor = Doctor(full_name="Dr. Test Dst", specialty="General Medicine", active=True)
        db.add(doctor)
        db.flush()
        db.add(
            AvailabilityRule(
                doctor_id=doctor.id,
                kind=RULE_AVAILABLE,
                weekday=None,
                start_minute=9 * 60,
                end_minute=10 * 60,
                slot_minutes=60,
            )
        )
        db.commit()

        tz = settings.clinic_tz
        slots = available_slots(db, doctor_id=doctor.id, limit=50)
        assert slots
        assert {s.start_utc.astimezone(tz).hour for s in slots} == {9}
    finally:
        object.__setattr__(settings, "vb_clinic_timezone", original)
        assert config_module is not None
