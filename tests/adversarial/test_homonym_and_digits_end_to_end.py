"""C-33 and C-18, driven through the API the way a call would drive them."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select

from app.models import STATUS_ACTIVE, STATUS_CANCELLED, Appointment


def _book(api, session_id, *, name: str, specialty: str, slot_ordinal: int = 1):
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": specialty})
    api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})
    response = api.post(
        "/tools/book_appointment",
        {
            "session_id": session_id,
            "slot_ordinal": slot_ordinal,
            "patient_name": name,
            "idempotency_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "reference": body["reference"],
        "date": datetime.fromisoformat(body["starts_at_local"]).date().isoformat(),
        "doctor_name": body["doctor_name"],
    }


def test_two_ahmed_khans_the_same_day_cancel_the_right_one(api, session_id, db):
    """The reference is what tells them apart, and nothing else is consulted."""
    first = _book(api, session_id, name="Ahmed Khan", specialty="Cardiology")
    second = _book(api, session_id, name="Ahmed Khan", specialty="Dermatology")
    assert first["reference"] != second["reference"]

    response = api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": second["date"],
            "reference": second["reference"],
        },
    )
    assert response.status_code == 200
    assert response.json()["doctor_name"] == second["doctor_name"]

    remaining = db.execute(
        select(Appointment).where(Appointment.status == STATUS_ACTIVE)
    ).scalars().all()
    assert len(remaining) == 1

    cancelled = db.execute(
        select(Appointment).where(Appointment.status == STATUS_CANCELLED)
    ).scalar_one()
    assert cancelled.cancelled_at is not None


def test_a_denial_never_names_a_second_patient(api, session_id):
    """Enumerating candidates aloud would leak both people."""
    _book(api, session_id, name="Ahmed Khan", specialty="Cardiology")
    other = _book(api, session_id, name="Ahmed Khan", specialty="Dermatology")

    denial = api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": other["date"],
            "reference": "0000",
        },
    )
    assert denial.status_code == 403
    text = denial.text.lower()
    for leak in ("cardiology", "dermatology", "two", "which"):
        assert leak not in text


def test_a_cut_turn_mid_reference_costs_the_caller_nothing(api, session_id, booked):
    """The caller says '4-7', VAD ends the turn, they say '2-9'."""
    record = booked(name="Ahmed Khan")
    reference = record["reference"]

    first = api.post(
        "/tools/append_reference_digits",
        {"session_id": session_id, "fragment": reference[:2]},
    ).json()
    assert first["digits_collected"] == 2
    assert first["ready"] is False
    assert first["readback"] is None

    second = api.post(
        "/tools/append_reference_digits",
        {"session_id": session_id, "fragment": reference[2:]},
    ).json()
    assert second["digits_collected"] == 4
    assert second["ready"] is True
    assert second["readback"] == "-".join(reference)

    cancelled = api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": record["date"],
            "reference": reference,
        },
    )
    assert cancelled.status_code == 200


def test_saying_no_to_the_readback_clears_the_buffer(api, session_id):
    api.post("/tools/append_reference_digits", {"session_id": session_id, "fragment": "4 7 2 9"})
    cleared = api.post("/tools/clear_reference_digits", {"session_id": session_id}).json()
    assert cleared["digits_collected"] == 0
    assert cleared["ready"] is False

    resumed = api.post(
        "/tools/append_reference_digits", {"session_id": session_id, "fragment": "1"}
    ).json()
    assert resumed["digits_collected"] == 1


def test_three_bad_reads_exhaust_the_retries(api, session_id):
    exhausted = False
    for _ in range(3):
        api.post(
            "/tools/append_reference_digits", {"session_id": session_id, "fragment": "4 7 2 9"}
        )
        exhausted = api.post(
            "/tools/clear_reference_digits", {"session_id": session_id}
        ).json()["retries_exhausted"]
    assert exhausted is True


def test_a_retried_booking_produces_one_appointment_and_one_reference(api, session_id, db):
    """F15: a network timeout must not double-book or issue a second code."""
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
    api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})
    key = str(uuid.uuid4())
    payload = {
        "session_id": session_id,
        "slot_ordinal": 1,
        "patient_name": "Ahmed Khan",
        "idempotency_key": key,
    }

    first = api.post("/tools/book_appointment", payload)
    second = api.post("/tools/book_appointment", payload)

    assert first.status_code == second.status_code == 200
    assert first.json()["reference"] == second.json()["reference"]

    rows = db.execute(select(Appointment)).scalars().all()
    assert len(rows) == 1
