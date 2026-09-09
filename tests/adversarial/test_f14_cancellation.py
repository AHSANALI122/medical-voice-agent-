"""F14 — cancellation (C-31, C-28, C-37).

The acceptance criteria in spec F14 are three, and each one is a claim about
what an attacker cannot do rather than about what a caller can:

  1. cancelling an already-cancelled appointment is idempotent;
  2. a denied attempt produces exactly one audit row with the denial reason;
  3. no list tool exists at any privilege level.

**On "idempotent".** The second cancellation of the same appointment returns the
uniform failure, not a second confirmation. That is the reading this file
asserts, and it is deliberate: `match_cancellation_candidate` filters to active
rows, so a cancelled appointment is indistinguishable from a wrong reference,
which is exactly what C-32 demands. Idempotent here means *the database ends in
the same state and no second mutation happens* — not *the caller is told yes
twice*. Making the second call answer "already cancelled" would require widening
the authority query to cancelled rows, and that widening is what would turn the
cancel endpoint into an oracle for past appointments.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models import (
    ACTION_CANCEL,
    DECISION_ALLOWED,
    DECISION_DENIED,
    REASON_MATCH,
    STATUS_ACTIVE,
    STATUS_CANCELLED,
    Appointment,
    AuditEvent,
)
from app.security.reference import UNIFORM_FAILURE_TEXT
from tester.client import TOOLS


def _cancel(api, session_id, *, name, date, reference):
    return api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": name,
            "appointment_date": date,
            "reference": reference,
        },
    )


def _cancel_events(db) -> list[AuditEvent]:
    return list(
        db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == ACTION_CANCEL)
            .order_by(AuditEvent.id)
        )
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------
# The allowed path
# --------------------------------------------------------------------------


def test_a_full_match_cancels_and_writes_exactly_one_allowed_row(api, session_id, booked, db):
    record = booked(name="Ahmed Khan")

    response = _cancel(
        api,
        session_id,
        name=record["name"],
        date=record["date"],
        reference=record["reference"],
    )

    assert response.status_code == 200
    body = response.json()
    assert body["confirmed"] is True
    # It describes the one appointment it just cancelled and nothing else (C-37).
    assert body["doctor_name"] == record["doctor_name"]
    assert set(body) == {"confirmed", "doctor_name", "starts_at_local", "spoken"}
    # And it does not repeat the reference back on the way out (5.1).
    assert record["reference"] not in response.text

    rows = db.execute(select(Appointment)).scalars().all()
    assert [r.status for r in rows] == [STATUS_CANCELLED]
    assert rows[0].cancelled_at is not None

    events = _cancel_events(db)
    assert len(events) == 1
    assert (events[0].decision, events[0].reason) == (DECISION_ALLOWED, REASON_MATCH)
    assert events[0].target_appointment_id == rows[0].id


# --------------------------------------------------------------------------
# Acceptance 1 — already-cancelled is idempotent
# --------------------------------------------------------------------------


def test_cancelling_an_already_cancelled_appointment_changes_nothing(
    api, session_id, booked, db
):
    record = booked(name="Ahmed Khan")
    first = _cancel(
        api,
        session_id,
        name=record["name"],
        date=record["date"],
        reference=record["reference"],
    )
    assert first.status_code == 200

    appointment = db.execute(select(Appointment)).scalars().one()
    cancelled_at = appointment.cancelled_at

    second = _cancel(
        api,
        session_id,
        name=record["name"],
        date=record["date"],
        reference=record["reference"],
    )

    # The caller is told the same thing they would be told for a wrong
    # reference. They learn nothing about the appointment having existed.
    assert second.status_code == 403
    assert second.json()["detail"] == UNIFORM_FAILURE_TEXT

    db.expire_all()
    rows = db.execute(select(Appointment)).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == STATUS_CANCELLED
    # No second mutation: the timestamp is the one the first call wrote.
    assert rows[0].cancelled_at == cancelled_at


def test_the_second_cancellation_is_indistinguishable_from_a_wrong_reference(
    api, session_id, booked
):
    record = booked(name="Ahmed Khan")
    _cancel(
        api,
        session_id,
        name=record["name"],
        date=record["date"],
        reference=record["reference"],
    )

    repeat = _cancel(
        api,
        session_id,
        name=record["name"],
        date=record["date"],
        reference=record["reference"],
    )
    wrong = _cancel(
        api,
        session_id,
        name=record["name"],
        date=record["date"],
        reference="9999" if record["reference"] != "9999" else "1111",
    )

    assert repeat.status_code == wrong.status_code == 403
    assert repeat.json() == wrong.json()


# --------------------------------------------------------------------------
# Acceptance 2 — one audit row per denial, carrying the reason
# --------------------------------------------------------------------------


def test_every_denial_shape_writes_exactly_one_row_and_says_the_same_thing(
    api, session_id, booked, db
):
    """Wrong name, wrong date, wrong reference, no such record.

    Four different server-side reasons, four identical caller-facing answers,
    and exactly one audit row each.
    """
    record = booked(name="Ahmed Khan")
    other_day = "2030-01-15"

    attempts = [
        ("wrong name", "Bilal Ahmed", record["date"], record["reference"]),
        ("wrong date", record["name"], other_day, record["reference"]),
        ("wrong reference", record["name"], record["date"], "0000"),
        ("no such record", "Zainab Iqbal", other_day, "0001"),
    ]

    bodies = []
    for label, name, date, reference in attempts:
        before = len(_cancel_events(db))
        response = _cancel(api, session_id, name=name, date=date, reference=reference)
        after = _cancel_events(db)

        assert response.status_code == 403, label
        bodies.append(response.json())
        assert len(after) - before == 1, f"{label} wrote {len(after) - before} rows"
        assert after[-1].decision == DECISION_DENIED, label
        # The reason is recorded server-side and is never the caller's business.
        assert after[-1].reason, label
        assert after[-1].reason not in response.text, label

    # Every one of them said exactly the same thing.
    assert all(body == bodies[0] for body in bodies)
    assert bodies[0]["detail"] == UNIFORM_FAILURE_TEXT


def test_a_denial_audit_row_survives_the_403(api, session_id, booked, db):
    """Raising aborts the request. The trail must not abort with it.

    Otherwise an abuser discards their own record simply by being refused.
    """
    record = booked(name="Ahmed Khan")

    _cancel(api, session_id, name=record["name"], date=record["date"], reference="0000")

    denials = [e for e in _cancel_events(db) if e.decision == DECISION_DENIED]
    assert len(denials) == 1


def test_a_denial_row_names_no_appointment_it_did_not_match(api, session_id, booked, db):
    """The row must not point at the record the attacker was fishing for.

    A denied attempt that stamped `target_appointment_id` with the row it nearly
    matched would put "somebody asked about appointment 7" in the audit table,
    which is the same disclosure the endpoint refuses to make out loud.
    """
    record = booked(name="Ahmed Khan")
    _cancel(api, session_id, name=record["name"], date=record["date"], reference="0000")

    denial = [e for e in _cancel_events(db) if e.decision == DECISION_DENIED][-1]
    assert denial.target_appointment_id is None


# --------------------------------------------------------------------------
# Acceptance 3 — no list tool, at any privilege level
# --------------------------------------------------------------------------


def test_no_list_tool_exists_on_any_channel(api, app):
    """C-37. Every channel, not just the untrusted-looking ones."""
    routes = {getattr(route, "path", "") for route in app.routes}
    assert not [path for path in routes if "list" in path.lower()]

    for channel in ("web", "phone", "tester"):
        for name in ("list_my_appointments", "list_appointments", "my_appointments"):
            response = api.post(
                f"/tools/{name}", {"session_id": "x" * 12}, channel=channel
            )
            assert response.status_code == 404, (channel, name)


def test_the_published_tool_surface_holds_no_bulk_reader():
    for tool in TOOLS:
        assert "list" not in tool
        assert not tool.startswith("get_my_")
    assert "cancel_appointment" in TOOLS


def test_cancellation_returns_one_appointment_and_never_a_collection(
    api, session_id, booked
):
    """Two live appointments under one name; the answer still describes one.

    C-33's "which Ahmed Khan" question is settled in the F6 suite. What F14 owes
    is narrower and worth its own assertion: the response body must carry no
    collection at all, so there is no shape here that a second appointment could
    ever be appended to.
    """
    first = booked(name="Ahmed Khan", specialty="Cardiology")
    second = booked(name="Ahmed Khan", specialty="Dermatology")

    response = _cancel(
        api,
        session_id,
        name="Ahmed Khan",
        date=second["date"],
        reference=second["reference"],
    )

    assert response.status_code == 200
    body = response.json()
    assert not any(isinstance(value, list) for value in body.values())
    assert body["doctor_name"] == second["doctor_name"]
    # Nothing about the appointment it did not touch reached the caller.
    assert first["doctor_name"] not in response.text
    assert first["reference"] not in response.text


# --------------------------------------------------------------------------
# The session is not a credential (C-38)
# --------------------------------------------------------------------------


def test_a_session_from_one_channel_cannot_cancel_from_another(api, booked, session_id):
    record = booked(name="Ahmed Khan")

    response = api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": record["name"],
            "appointment_date": record["date"],
            "reference": record["reference"],
        },
        channel="phone",
    )

    assert response.status_code == 403
    assert response.json()["detail"] == UNIFORM_FAILURE_TEXT


def test_a_fresh_session_cancels_with_the_reference_and_nothing_else(api, booked, db):
    """Authority is the reference, not the session that booked it.

    A caller who hangs up and calls back must be able to cancel, and a caller
    who kept the session but not the reference must not.
    """
    record = booked(name="Ahmed Khan")

    callback = api.post("/tools/create_session", {"consent_given": True}).json()[
        "session_id"
    ]

    without_reference = _cancel(
        api, callback, name=record["name"], date=record["date"], reference="0000"
    )
    assert without_reference.status_code == 403

    with_reference = _cancel(
        api,
        callback,
        name=record["name"],
        date=record["date"],
        reference=record["reference"],
    )
    assert with_reference.status_code == 200

    assert db.execute(select(Appointment.status)).scalars().all() == [STATUS_CANCELLED]


def test_a_cancelled_slot_becomes_bookable_again(api, session_id, booked, db):
    """The partial unique index is scoped to active rows, so it had better be."""
    record = booked(name="Ahmed Khan")
    assert (
        _cancel(
            api,
            session_id,
            name=record["name"],
            date=record["date"],
            reference=record["reference"],
        ).status_code
        == 200
    )

    fresh = api.post("/tools/create_session", {"consent_given": True}).json()[
        "session_id"
    ]
    api.post("/tools/search_doctors", {"session_id": fresh, "specialty": "Cardiology"})
    api.post("/tools/get_available_slots", {"session_id": fresh, "doctor_ordinal": 1})
    rebooked = api.post(
        "/tools/book_appointment",
        {
            "session_id": fresh,
            "slot_ordinal": 1,
            "patient_name": "Sana Malik",
            "idempotency_key": str(uuid.uuid4()),
        },
    )

    assert rebooked.status_code == 200
    statuses = sorted(db.execute(select(Appointment.status)).scalars().all())
    assert statuses == [STATUS_ACTIVE, STATUS_CANCELLED]
