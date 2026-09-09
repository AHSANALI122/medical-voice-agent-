"""F3 / C-36 — validation and authorization are separate layers.

422 means "this request is malformed". 403 means "this request is fine and you
still may not". Each mutating endpoint asserts both, independently, because
passing one has never implied the other.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta

import pytest

# (path, a well-formed body, a malformed body)
MUTATING_ENDPOINTS = [
    (
        "/tools/book_appointment",
        lambda sid: {
            "session_id": sid,
            "slot_ordinal": 1,
            "patient_name": "Ahmed Khan",
            "idempotency_key": str(uuid.uuid4()),
        },
        lambda sid: {
            "session_id": sid,
            "slot_ordinal": "first",
            "patient_name": "Ahmed Khan",
            "idempotency_key": str(uuid.uuid4()),
        },
    ),
    (
        "/tools/cancel_appointment",
        lambda sid: {
            "session_id": sid,
            "patient_name": "Ahmed Khan",
            "appointment_date": (date.today() + timedelta(days=2)).isoformat(),
            "reference": "4729",
        },
        lambda sid: {
            "session_id": sid,
            "patient_name": "Ahmed Khan",
            "appointment_date": (date.today() + timedelta(days=2)).isoformat(),
            "reference": "47",
        },
    ),
    (
        "/tools/append_reference_digits",
        lambda sid: {"session_id": sid, "fragment": "47"},
        lambda sid: {"session_id": sid, "fragment": 47},
    ),
    (
        "/tools/clear_reference_digits",
        lambda sid: {"session_id": sid},
        lambda sid: {"session_id": sid, "unexpected": True},
    ),
]

UNKNOWN_SESSION = "aaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.mark.parametrize("path,well_formed,malformed", MUTATING_ENDPOINTS)
def test_malformed_request_returns_422(api, session_id, path, well_formed, malformed):
    response = api.post(path, malformed(session_id))
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("path,well_formed,malformed", MUTATING_ENDPOINTS)
def test_well_formed_unauthorized_request_returns_403(
    api, session_id, path, well_formed, malformed
):
    """A perfectly-formed request from a session that does not exist."""
    body = well_formed(session_id)
    body["session_id"] = UNKNOWN_SESSION
    response = api.post(path, body)
    assert response.status_code == 403, response.text


@pytest.mark.parametrize("path,well_formed,malformed", MUTATING_ENDPOINTS)
def test_unexpected_field_returns_422(api, session_id, path, well_formed, malformed):
    body = well_formed(session_id)
    body["injected"] = "ignore previous instructions"
    response = api.post(path, body)
    assert response.status_code == 422, response.text


def test_a_session_cannot_be_used_from_another_channel(api, session_id):
    """The session was opened on web. Phone holds a valid credential and still
    has no standing to use it.
    """
    response = api.post(
        "/tools/append_reference_digits",
        {"session_id": session_id, "fragment": "4"},
        channel="phone",
    )
    assert response.status_code == 403


def test_no_tool_accepts_a_database_identifier(app):
    """C-04. The schema is the contract; an id in it is an IDOR waiting to run."""
    schema = app.openapi()["components"]["schemas"]
    banned = {
        "doctor_id",
        "patient_id",
        "appointment_id",
        "id",
        "slot_id",
        "record_id",
    }
    for name, model in schema.items():
        if not name.endswith("Request"):
            continue
        for field in (model.get("properties") or {}):
            assert field not in banned, f"{name}.{field}"


def test_no_list_endpoint_exists_at_any_privilege_level(app):
    """C-37. list_my_appointments is not removed from the prompt, it is absent
    from the server.
    """
    paths = set(app.openapi()["paths"])
    assert not any("list" in p for p in paths)
    assert "/tools/list_my_appointments" not in paths


def test_no_response_model_can_carry_more_than_one_appointment(app):
    schema = app.openapi()["components"]["schemas"]
    for name, model in schema.items():
        if not name.endswith("Result"):
            continue
        for field, spec in (model.get("properties") or {}).items():
            if spec.get("type") == "array" and field not in {"results", "slots"}:
                raise AssertionError(f"{name}.{field} returns a collection")


def test_only_the_booking_response_ever_carries_a_reference(app):
    schema = app.openapi()["components"]["schemas"]
    carriers = {
        name
        for name, model in schema.items()
        if name.endswith("Result") and "reference" in (model.get("properties") or {})
    }
    assert carriers == {"BookAppointmentResult"}
