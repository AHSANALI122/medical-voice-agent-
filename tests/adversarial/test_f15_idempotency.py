"""F15 — idempotency, and the reference-harvesting hole under it.

Acceptance in spec F15 is one sentence: a retried call after a network timeout
produces exactly one appointment row and does not issue a second reference.

The adversarial half is the part the sentence does not say. `book_appointment`
is the only endpoint in the system that returns a booking reference, and the
idempotency key is the argument that makes it return one a second time. The key
arrives from the agent layer, and section 8 is explicit that the model will
eventually send attacker-chosen arguments. So the key's own entropy cannot be
what protects the reference — the key is namespaced with the server-minted
session id instead, and these tests are what say so.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models import (
    ACTION_BOOK,
    DECISION_ALLOWED,
    REASON_IDEMPOTENT_REPLAY,
    REASON_MATCH,
    Appointment,
    AuditEvent,
)
from app.security.crypto import reference_hmac
from app.services import booking


def _offer(api, session_id, specialty="Cardiology"):
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": specialty})
    api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})


def _book(api, session_id, *, key, name="Ahmed Khan", slot_ordinal=1):
    return api.post(
        "/tools/book_appointment",
        {
            "session_id": session_id,
            "slot_ordinal": slot_ordinal,
            "patient_name": name,
            "idempotency_key": key,
        },
    )


def _book_events(db):
    return list(
        db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == ACTION_BOOK)
            .order_by(AuditEvent.id)
        )
        .scalars()
        .all()
    )


# --------------------------------------------------------------------------
# The acceptance criterion
# --------------------------------------------------------------------------


def test_a_retried_call_books_once_and_issues_one_reference(api, session_id, db):
    """The network-timeout retry: same session, same key, same bytes of intent."""
    key = str(uuid.uuid4())
    _offer(api, session_id)

    first = _book(api, session_id, key=key)
    second = _book(api, session_id, key=key)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()

    rows = db.execute(select(Appointment)).scalars().all()
    assert len(rows) == 1

    # Not merely "the same string came back" — the row still carries the digest
    # of that one reference, so no second reference was ever minted.
    digest, _key_id = reference_hmac(first.json()["reference"])
    assert rows[0].reference_hmac == digest


def test_a_replay_is_audited_as_a_replay_and_not_as_a_second_booking(
    api, session_id, db
):
    key = str(uuid.uuid4())
    _offer(api, session_id)
    _book(api, session_id, key=key)
    _book(api, session_id, key=key)

    events = _book_events(db)
    assert [(e.decision, e.reason) for e in events] == [
        (DECISION_ALLOWED, REASON_MATCH),
        (DECISION_ALLOWED, REASON_IDEMPOTENT_REPLAY),
    ]
    assert events[0].target_appointment_id == events[1].target_appointment_id


def test_a_replay_does_not_spend_the_daily_booking_budget(api, session_id, db, monkeypatch):
    """F8's per-name cap counts appointments, not requests.

    A caller whose confirmation was lost on the wire has booked once. Charging
    the retry would let a flaky network exhaust a real caller's budget.
    """
    from app.config import get_settings

    limit = get_settings().max_bookings_per_name_per_day
    keys = [str(uuid.uuid4()) for _ in range(limit)]

    for index, key in enumerate(keys):
        _offer(api, session_id, specialty="Cardiology" if index % 2 == 0 else "Dermatology")
        assert _book(api, session_id, key=key).status_code == 200, index
        # Retry every one of them.
        assert _book(api, session_id, key=key).status_code == 200, index

    assert len(db.execute(select(Appointment)).scalars().all()) == limit

    _offer(api, session_id, specialty="Neurology")
    over = _book(api, session_id, key=str(uuid.uuid4()))
    assert over.status_code == 429


# --------------------------------------------------------------------------
# The hole: an idempotency key is a request for a reference
# --------------------------------------------------------------------------


def test_the_key_is_namespaced_by_session_not_only_by_channel():
    key = str(uuid.uuid4())
    mine = booking.scoped_idempotency_key(
        channel="web", session_id="session-a", client_key=key
    )
    theirs = booking.scoped_idempotency_key(
        channel="web", session_id="session-b", client_key=key
    )
    other_channel = booking.scoped_idempotency_key(
        channel="phone", session_id="session-a", client_key=key
    )

    assert mine != theirs
    assert mine != other_channel
    assert "session-a" in mine


def test_a_second_caller_reusing_the_key_never_receives_the_first_reference(api, db):
    """The attack, run end to end.

    A compromised model can send any idempotency key it likes, including one it
    saw or guessed. Under a channel-only namespace that request would replay
    somebody else's booking and speak their reference aloud — which is the whole
    authority to cancel it (5.2).
    """
    shared_key = str(uuid.uuid4())

    victim = api.post("/tools/create_session", {"consent_given": True}).json()[
        "session_id"
    ]
    _offer(api, victim)
    booked = _book(api, victim, key=shared_key, name="Ahmed Khan")
    assert booked.status_code == 200
    victim_reference = booked.json()["reference"]

    attacker = api.post("/tools/create_session", {"consent_given": True}).json()[
        "session_id"
    ]
    _offer(api, attacker)
    stolen = _book(api, attacker, key=shared_key, name="Attacker Name")

    assert victim_reference not in stolen.text
    if stolen.status_code == 200:
        # It booked the attacker their own slot, with their own new reference.
        assert stolen.json()["reference"] != victim_reference
    else:
        assert stolen.status_code in (409, 429)

    # And the victim's appointment is untouched.
    digest, _ = reference_hmac(victim_reference)
    assert (
        db.execute(
            select(Appointment).where(Appointment.reference_hmac == digest)
        ).scalar_one()
        is not None
    )


def test_a_fixed_low_entropy_key_leaks_nothing_across_sessions(api):
    """The realistic version: a model that always emits the same UUID."""
    constant = "00000000-0000-0000-0000-000000000000"

    references = []
    for _ in range(2):
        session = api.post("/tools/create_session", {"consent_given": True}).json()[
            "session_id"
        ]
        _offer(api, session)
        response = _book(api, session, key=constant, name="Ahmed Khan")
        assert response.status_code == 200, response.text
        references.append(response.json()["reference"])

    # Two sessions, one key, two distinct bookings. Neither replayed the other.
    assert references[0] != references[1] or len(set(references)) == 2


def test_a_replay_cannot_cross_channels(api, session_id):
    """Session ids are already channel-bound; the key does not loosen that."""
    key = str(uuid.uuid4())
    _offer(api, session_id)
    assert _book(api, session_id, key=key).status_code == 200

    crossed = api.post(
        "/tools/book_appointment",
        {
            "session_id": session_id,
            "slot_ordinal": 1,
            "patient_name": "Ahmed Khan",
            "idempotency_key": key,
        },
        channel="phone",
    )
    assert crossed.status_code == 403


# --------------------------------------------------------------------------
# Shape
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "not-a-uuid", "1234", "0" * 40])
def test_a_malformed_key_is_a_422_and_never_an_authorization_decision(
    api, session_id, bad
):
    """C-36: validation rejects the shape; it decides nothing about permission."""
    _offer(api, session_id)
    response = _book(api, session_id, key=bad)
    assert response.status_code == 422


def test_the_reference_is_never_stored_in_plaintext_by_the_replay_path(
    api, session_id, db
):
    key = str(uuid.uuid4())
    _offer(api, session_id)
    reference = _book(api, session_id, key=key).json()["reference"]
    _book(api, session_id, key=key)

    row = db.execute(select(Appointment)).scalars().one()
    blob = " ".join(
        str(value) for value in (row.idempotency_key, row.reference_key_id, row.status)
    )
    assert reference not in blob
    assert reference.encode() not in row.reference_hmac
