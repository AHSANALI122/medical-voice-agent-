"""F11 — structured events, the 30-day purge, and what must never be in them.

The acceptance criteria are "redactor fixtures pass with zero leaked names or
references" (in `tests/unit/test_f11_redaction.py`) and "purge removes records
older than 30 days". This file covers the purge and the property that makes the
event table safe in the first place: there is no column a transcript could be
written to.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import String, Text, select

from app.models import (
    OUTCOME_DENIED,
    OUTCOME_ESCALATED,
    OUTCOME_INVALID,
    OUTCOME_OK,
    OUTCOME_THROTTLED,
    UNKNOWN_TOOL,
    AuditEvent,
    ObservabilityEvent,
)
from app.services import observability


def _events(db):
    return list(
        db.execute(select(ObservabilityEvent).order_by(ObservabilityEvent.id))
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------
# The event stream
# --------------------------------------------------------------------------


def test_every_tool_call_produces_one_event(api, session_id, db):
    before = len(_events(db))
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
    api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})
    after = _events(db)

    assert len(after) - before == 2
    assert [e.tool for e in after[-2:]] == ["search_doctors", "get_available_slots"]
    assert all(e.latency_ms > 0 for e in after[-2:])
    assert all(e.session_id == session_id for e in after[-2:])
    assert all(e.channel == "web" for e in after[-2:])


def test_the_event_carries_session_turn_latency_and_outcome(api, session_id, db):
    """The vocabulary spec F11 asks for, in one row."""
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
    event = _events(db)[-1]

    assert event.session_id == session_id
    assert event.turn is not None
    assert event.latency_ms > 0
    assert event.outcome == OUTCOME_OK
    assert event.escalated is False
    assert event.correlation_id


def test_the_correlation_id_comes_back_on_the_response(api, session_id, db):
    response = api.post(
        "/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"}
    )
    correlation_id = response.headers.get("x-correlation-id")
    assert correlation_id
    assert _events(db)[-1].correlation_id == correlation_id


def test_outcomes_map_from_the_status_code(api, session_id, db):
    # 422 — a shape problem.
    api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 0})
    assert _events(db)[-1].outcome == OUTCOME_INVALID

    # 403 — an authorization problem. Separate layer, separate outcome (C-36).
    api.post(
        "/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 19}
    )
    assert _events(db)[-1].outcome == OUTCOME_DENIED


def test_an_escalation_is_visible_in_the_event_stream(api, session_id, db):
    api.post(
        "/tools/screen_turn",
        {"session_id": session_id, "utterance": "I'm having chest pain"},
    )
    event = _events(db)[-1]
    assert event.escalated is True
    assert event.outcome == OUTCOME_ESCALATED


def test_a_throttled_call_is_recorded_as_throttled(api, app, db):
    from fastapi.testclient import TestClient

    from tests.conftest import SignedClient

    caller = SignedClient(TestClient(app, client=("203.0.113.9", 40000)))
    limit = 3
    for _ in range(limit + 1):
        caller.post("/tools/create_session", {"consent_given": True})

    assert _events(db)[-1].outcome == OUTCOME_THROTTLED


# --------------------------------------------------------------------------
# What must not be in an event
# --------------------------------------------------------------------------


def test_the_event_table_has_no_free_text_column():
    """The structural claim. C-09 is about transcripts becoming a PHI sink, and
    the answer is not a carefully redacted transcript column — it is no column
    a transcript could be written to.
    """
    columns = ObservabilityEvent.__table__.columns
    textual = [c.name for c in columns if isinstance(c.type, (String, Text))]
    assert sorted(textual) == ["channel", "correlation_id", "outcome", "session_id", "tool"]


def test_a_probed_path_cannot_choose_what_lands_in_the_tool_column(api, db):
    """The last path segment is whatever the caller typed."""
    api.post("/tools/'; DROP TABLE appointments; --", {"session_id": "x" * 12})
    api.post("/tools/list_my_appointments", {"session_id": "x" * 12})

    recent = _events(db)[-2:]
    assert all(e.tool == UNKNOWN_TOOL for e in recent)
    assert all(e.tool in observability.KNOWN_TOOLS or e.tool == UNKNOWN_TOOL for e in _events(db))


def test_no_event_carries_a_name_a_reference_or_symptom_text(api, session_id, booked, db):
    record = booked(name="Ahmed Khan")
    api.post(
        "/tools/screen_turn",
        {"session_id": session_id, "utterance": "I have a fever and a rash"},
    )
    api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": record["date"],
            "reference": "0000",
        },
    )

    for event in _events(db):
        blob = " ".join(
            str(v)
            for v in (event.tool, event.channel, event.outcome, event.correlation_id)
        )
        assert "Ahmed" not in blob
        assert "fever" not in blob
        assert "rash" not in blob
        assert record["reference"] not in blob


def test_an_unauthorized_session_id_is_not_written_into_telemetry(api, db):
    """A caller who names a session they have no claim to must not get that id
    recorded under their own request — that would make the event table a log of
    which session ids somebody had been guessing at.
    """
    guess = "z" * 32
    api.post("/tools/search_doctors", {"session_id": guess, "specialty": "Cardiology"})

    event = _events(db)[-1]
    assert event.outcome == OUTCOME_DENIED
    assert event.session_id is None


def test_an_unauthenticated_probe_records_no_channel(client, db):
    """The channel is stamped only after the signature verifies, so an event for
    a rejected request cannot be made to claim a channel it never proved.
    """
    client.post(
        "/tools/create_session",
        content=json.dumps({"consent_given": True}).encode(),
        headers={"content-type": "application/json", "x-vb-channel": "web"},
    )
    event = _events(db)[-1]
    assert event.status_code == 401
    assert event.channel is None


def test_the_log_line_is_parseable_json_with_no_free_text(db, api, session_id):
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
    line = observability.log_line(_events(db)[-1])
    parsed = json.loads(line)
    assert parsed["event"] == "tool_call"
    assert set(parsed) == {
        "channel",
        "correlation_id",
        "escalated",
        "event",
        "latency_ms",
        "outcome",
        "session_id",
        "status",
        "tool",
        "turn",
    }


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------


def test_purge_removes_records_older_than_thirty_days(db):
    now = datetime.now(timezone.utc)
    for age_days in (1, 29, 30, 31, 365):
        event = observability.record_tool_call(
            db,
            correlation_id=uuid.uuid4().hex,
            tool="search_doctors",
            status_code=200,
            latency_ms=1.0,
        )
        event.created_at = now - timedelta(days=age_days)
    db.commit()

    removed = observability.purge(db, now=now)
    db.commit()

    # 30 days exactly is inside the window; 31 and 365 are not.
    assert removed == 2
    remaining = sorted((now - e.created_at).days for e in _events(db))
    assert remaining == [1, 29, 30]


def test_purge_is_a_no_op_on_a_fresh_database(db):
    assert observability.purge(db) == 0


def test_purge_never_touches_the_audit_trail(db, api, session_id, booked):
    """F17: `audit_events` has no delete path in application code, and the
    retention job does not become one.
    """
    booked(name="Ahmed Khan")
    before = len(db.execute(select(AuditEvent.id)).scalars().all())

    for event in _events(db):
        event.created_at = datetime.now(timezone.utc) - timedelta(days=400)
    db.commit()

    observability.purge(db)
    db.commit()

    assert _events(db) == []
    assert len(db.execute(select(AuditEvent.id)).scalars().all()) == before


def test_no_code_path_deletes_or_updates_an_audit_row_via_the_purge():
    import pathlib

    source = (
        pathlib.Path(__file__).resolve().parents[2] / "app" / "services" / "observability.py"
    ).read_text(encoding="utf-8")
    assert "AuditEvent" not in source


# --------------------------------------------------------------------------
# Telemetry must never be able to break the request
# --------------------------------------------------------------------------


def test_a_failing_event_write_does_not_fail_the_booking(api, session_id, monkeypatch, db):
    """An event must not be able to roll back the mutation it describes — the
    exact opposite of the audit rule, and deliberately so.
    """
    from sqlalchemy import select as sa_select

    from app.models import Appointment

    def explode(*args, **kwargs):
        raise RuntimeError("metrics backend is on fire")

    monkeypatch.setattr(observability, "record_tool_call", explode)

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

    assert response.status_code == 200
    assert len(db.execute(sa_select(Appointment.id)).scalars().all()) == 1
