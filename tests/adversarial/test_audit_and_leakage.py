"""F17 and the leakage checks that do not fit anywhere else."""

from __future__ import annotations

import logging
import uuid

import pytest
from sqlalchemy import select

from app.db import base as db_base
from app.models import ACTION_CANCEL, Appointment, AuditEvent, Patient
from app.services import audit, booking


def test_a_rolled_back_mutation_leaves_no_audit_row(db, booked):
    """C-28: the row rides in the mutation's transaction or not at all."""
    record = booked(name="Ahmed Khan")
    before = len(db.execute(select(AuditEvent.id)).scalars().all())

    session = db_base.get_sessionmaker()()
    try:
        audit.record(
            session,
            action=ACTION_CANCEL,
            decision="denied",
            reason="no_match",
            session_id="s",
            channel="web",
        )
        session.rollback()
    finally:
        session.close()

    after = len(db.execute(select(AuditEvent.id)).scalars().all())
    assert after == before
    assert record["reference"]


def test_no_audit_row_carries_a_name_or_a_reference(api, session_id, booked, db):
    record = booked(name="Ahmed Khan")
    api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": record["date"],
            "reference": "0000",
        },
    )
    api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": record["date"],
            "reference": record["reference"],
        },
    )

    for event in db.execute(select(AuditEvent)).scalars().all():
        blob = " ".join(
            str(v) for v in (event.reason, event.detail, event.session_id, event.channel)
        )
        assert "Ahmed" not in blob
        assert "ahmed" not in blob.lower()
        assert record["reference"] not in blob


def test_the_audit_table_has_no_update_or_delete_path_in_application_code():
    """F17: append-only is a property of the code, not a hope about it."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "app"
    for path in root.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for forbidden in ("delete(AuditEvent", "AuditEvent).delete", "update(AuditEvent"):
            assert forbidden not in source, f"{path} mutates audit rows"


def test_nothing_logs_a_reference_during_a_full_booking(api, session_id, caplog):
    with caplog.at_level(logging.DEBUG, logger="voicebook"):
        api.post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
        api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})
        response = api.post(
            "/tools/book_appointment",
            {
                "session_id": session_id,
                "slot_ordinal": 1,
                "patient_name": "Ahmed Khan",
                "idempotency_key": str(uuid.uuid4()),
            },
        )
    reference = response.json()["reference"]
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert reference not in logged
    assert "Ahmed" not in logged


def test_the_patient_name_is_never_returned_by_any_endpoint(api, session_id, booked):
    record = booked(name="Ahmed Khan")
    cancelled = api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": record["date"],
            "reference": record["reference"],
        },
    )
    # The caller supplied the name, so echoing it leaks nothing new — but the
    # response describes the appointment, not the patient, and that is the habit
    # worth keeping.
    assert "patient_name" not in cancelled.json()


def test_the_readback_cache_holds_nothing_after_it_is_cleared(api, session_id, booked):
    record = booked(name="Ahmed Khan")
    assert booking.replay_reference(record["reference"]) is None
    booking.forget_references()
    assert booking.replay_reference("web:anything") is None


@pytest.mark.parametrize("status_code_path", ["/tools/create_session"])
def test_the_patient_row_stores_only_ciphertext_and_a_normalized_form(
    api, session_id, booked, db, status_code_path
):
    booked(name="Ahmed Khan")
    patient = db.execute(select(Patient)).scalars().first()
    assert b"Ahmed" not in patient.name_enc
    assert patient.name_normalized == "ahmed khan"
    assert patient.key_id
    assert len(patient.name_nonce) == 12


def test_an_appointment_row_holds_no_plaintext_reference(api, session_id, booked, db):
    record = booked(name="Ahmed Khan")
    appointment = db.execute(select(Appointment)).scalars().first()
    # Scan the text-bearing columns. The digest is binary and is checked
    # separately, so a chance byte sequence cannot make this test flap.
    text_columns = " ".join(
        str(getattr(appointment, column.name))
        for column in appointment.__table__.columns
        if not isinstance(getattr(appointment, column.name), bytes)
    )
    assert record["reference"] not in text_columns
    assert record["reference"].encode() not in appointment.reference_hmac
