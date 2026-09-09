"""F0 — schema, encryption, seed, persistence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.db import base as db_base
from app.db.seed import UnseededDatabase, assert_synthetic, seed
from app.models import (
    SEED_MARKER_KEY,
    STATUS_ACTIVE,
    STATUS_CANCELLED,
    Appointment,
    Base,
    Doctor,
    Meta,
    Patient,
)
from app.security.crypto import decrypt_field, encrypt_field, reference_hmac


def test_seed_has_enough_doctors_and_specialties(db):
    doctors = db.execute(select(Doctor)).scalars().all()
    assert len(doctors) >= 8
    assert len({d.specialty for d in doctors}) >= 5


def test_seed_is_idempotent(db):
    before = len(db.execute(select(Doctor)).scalars().all())
    created = seed(db)
    after = len(db.execute(select(Doctor)).scalars().all())
    assert created is False
    assert before == after


def test_boot_refuses_a_database_without_the_synthetic_marker(db):
    db.delete(db.get(Meta, SEED_MARKER_KEY))
    db.commit()
    with pytest.raises(UnseededDatabase):
        assert_synthetic(db)


def test_wal_is_enabled(tmp_path: Path):
    path = str(tmp_path / "wal.db")
    engine = db_base.build_engine(path)
    with engine.connect() as conn:
        mode = conn.execute(text("PRAGMA journal_mode")).scalar_one()
    assert mode.lower() == "wal"
    engine.dispose()


def test_patient_name_is_unreadable_through_the_sqlite_cli(tmp_path: Path):
    """C-08: the ciphertext on disk must not contain the name."""
    path = str(tmp_path / "phi.db")
    engine = db_base.build_engine(path)
    db_base.set_engine(engine)
    Base.metadata.create_all(engine)

    ciphertext, nonce, key_id = encrypt_field("Ahmed Khan")
    with db_base.session_scope() as db:
        db.add(
            Patient(
                name_enc=ciphertext,
                name_nonce=nonce,
                key_id=key_id,
                name_normalized="ahmed khan",
            )
        )
    engine.dispose()

    raw = Path(path).read_bytes()
    assert b"Ahmed Khan" not in raw
    # And the same through the CLI's own reader, not just a byte scan.
    conn = sqlite3.connect(path)
    stored = conn.execute("select name_enc from patients").fetchone()[0]
    conn.close()
    assert b"Ahmed Khan" not in stored
    assert decrypt_field(ciphertext, nonce, key_id) == "Ahmed Khan"


def test_reference_never_appears_in_plaintext_on_disk(tmp_path: Path, db):
    """F0 acceptance: only the HMAC is stored."""
    digest, key_id = reference_hmac("4729")
    doctor = db.execute(select(Doctor)).scalars().first()
    patient = Patient(
        name_enc=b"x", name_nonce=b"y" * 12, key_id=key_id, name_normalized="ahmed khan"
    )
    db.add(patient)
    db.flush()
    from datetime import datetime, timedelta, timezone

    start = datetime.now(timezone.utc) + timedelta(days=1)
    db.add(
        Appointment(
            doctor_id=doctor.id,
            patient_id=patient.id,
            slot_start_utc=start,
            slot_end_utc=start + timedelta(minutes=30),
            status=STATUS_ACTIVE,
            reference_hmac=digest,
            reference_key_id=key_id,
        )
    )
    db.commit()

    rows = db.execute(text("select reference_hmac from appointments")).all()
    assert rows
    for (value,) in rows:
        assert b"4729" not in value
        assert value == digest


def test_one_active_appointment_per_doctor_slot(db):
    """C-12: the constraint decides the race, not the application."""
    from datetime import datetime, timedelta, timezone

    doctor = db.execute(select(Doctor)).scalars().first()
    start = datetime.now(timezone.utc) + timedelta(days=2)

    def make(reference: str) -> Appointment:
        digest, key_id = reference_hmac(reference)
        patient = Patient(
            name_enc=b"x", name_nonce=b"y" * 12, key_id=key_id, name_normalized="a b"
        )
        db.add(patient)
        db.flush()
        return Appointment(
            doctor_id=doctor.id,
            patient_id=patient.id,
            slot_start_utc=start,
            slot_end_utc=start + timedelta(minutes=30),
            status=STATUS_ACTIVE,
            reference_hmac=digest,
            reference_key_id=key_id,
        )

    first = make("1111")
    db.add(first)
    db.commit()

    db.add(make("2222"))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()

    # Once the first is cancelled the slot frees up: the index is partial.
    db.get(Appointment, first.id).status = STATUS_CANCELLED
    db.commit()
    db.add(make("3333"))
    db.commit()


def test_reference_is_unique_among_active_appointments_only(db):
    from datetime import datetime, timedelta, timezone

    doctors = db.execute(select(Doctor)).scalars().all()
    digest, key_id = reference_hmac("5555")
    start = datetime.now(timezone.utc) + timedelta(days=3)

    def make(doctor_id: int) -> Appointment:
        patient = Patient(
            name_enc=b"x", name_nonce=b"y" * 12, key_id=key_id, name_normalized="a b"
        )
        db.add(patient)
        db.flush()
        return Appointment(
            doctor_id=doctor_id,
            patient_id=patient.id,
            slot_start_utc=start,
            slot_end_utc=start + timedelta(minutes=30),
            status=STATUS_ACTIVE,
            reference_hmac=digest,
            reference_key_id=key_id,
        )

    first = make(doctors[0].id)
    db.add(first)
    db.commit()

    db.add(make(doctors[1].id))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()

    db.get(Appointment, first.id).status = STATUS_CANCELLED
    db.commit()
    db.add(make(doctors[1].id))
    db.commit()


def test_no_reason_for_visit_column_exists_anywhere():
    """Non-goal made structural: symptoms have no door to walk through."""
    forbidden = {"reason", "symptom", "symptoms", "complaint", "notes", "condition"}
    # audit_events.reason is a denial code, not a clinical one, and it is
    # written from a closed server-side vocabulary — never from caller speech.
    clinical_tables = {"patients", "appointments", "sessions"}
    for name, table in Base.metadata.tables.items():
        if name not in clinical_tables:
            continue
        for column in table.columns:
            assert column.name.lower() not in forbidden, f"{name}.{column.name}"
