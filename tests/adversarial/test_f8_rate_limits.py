"""F8 — rate limits and abuse controls (C-07, C-14, C-23, C-29, C-34).

These are attack tests, not capacity tests. Each one asks the same question from
a different angle: can a caller who is over budget get the budget to forget?

The reference-lockout half of F8 lives in test_reference_brute_force.py, which
already proves the fifth guess locks the guesser and that a second caller from
another address holding the correct reference still cancels. This file covers
the four counting budgets.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.models import (
    ACTION_RATE_LIMIT,
    DECISION_DENIED,
    REASON_RATE_LIMITED,
    STATUS_ACTIVE,
    STATUS_CANCELLED,
    Appointment,
    AuditEvent,
    RateLimitBucket,
)
from app.security import rate_limit


def _open_session(api) -> "object":
    return api.post("/tools/create_session", {"consent_given": True})


def _book(api, session_id, *, name: str, slot_ordinal: int = 1):
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
    api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})
    return api.post(
        "/tools/book_appointment",
        {
            "session_id": session_id,
            "slot_ordinal": slot_ordinal,
            "patient_name": name,
            "idempotency_key": str(uuid.uuid4()),
        },
    )


# ------------------------------------------------------------ call budgets


def test_the_fourth_call_from_one_source_in_a_day_is_refused(api):
    limit = get_settings().max_sessions_per_ip_per_day
    for _ in range(limit):
        assert _open_session(api).status_code == 200

    refused = _open_session(api)
    assert refused.status_code == 429
    assert refused.json()["detail"] == rate_limit.RATE_LIMITED_TEXT


def test_reconnecting_does_not_reset_the_call_budget(api):
    """A reconnect mints a fresh session id, which is exactly why no budget is
    keyed on one (C-23). Opening a new session spends the budget; it never
    restores it.
    """
    limit = get_settings().max_sessions_per_ip_per_day
    ids = []
    for _ in range(limit):
        response = _open_session(api)
        assert response.status_code == 200
        ids.append(response.json()["session_id"])

    # Every reconnect produced a distinct session, and the budget counted them
    # all rather than starting over at each one.
    assert len(set(ids)) == limit
    assert _open_session(api).status_code == 429


def test_a_refusal_does_not_extend_the_callers_own_window(api, db):
    """Being refused must not push the window out, or a caller who keeps a dead
    line open is serving themselves an ever-growing sentence. The refusal is
    counted — that is how repeat hammering is visible — but the clock does not
    restart.
    """
    limit = get_settings().max_sessions_per_ip_per_day
    for _ in range(limit):
        assert _open_session(api).status_code == 200

    assert _open_session(api).status_code == 429
    bucket = _bucket(db, rate_limit.SCOPE_SESSION_IP)
    window_start, count = bucket.window_start_utc, bucket.count

    assert _open_session(api).status_code == 429
    db.expire_all()
    bucket = _bucket(db, rate_limit.SCOPE_SESSION_IP)
    assert bucket.window_start_utc == window_start
    assert bucket.count == count + 1


def test_a_refused_call_writes_one_audit_row_naming_the_scope(api, db):
    limit = get_settings().max_sessions_per_ip_per_day
    for _ in range(limit):
        _open_session(api)
    assert _open_session(api).status_code == 429

    rows = _rate_limit_rows(db)
    assert len(rows) == 1
    assert rows[0].decision == DECISION_DENIED
    assert rows[0].reason == REASON_RATE_LIMITED
    # The scope is in the row and not in the response: a caller who learns which
    # budget they tripped learns which one to work around.
    assert rows[0].detail == rate_limit.SCOPE_SESSION_IP


def test_hammering_a_spent_budget_cannot_fill_the_audit_table(api, db):
    """A rate limit that writes a row per refused request is a way of filling a
    disk. One row records the event; the bucket's count records the hammering.
    """
    limit = get_settings().max_sessions_per_ip_per_day
    for _ in range(limit):
        _open_session(api)
    for _ in range(20):
        assert _open_session(api).status_code == 429

    assert len(_rate_limit_rows(db)) == 1
    db.expire_all()
    assert _bucket(db, rate_limit.SCOPE_SESSION_IP).count == limit + 20


def test_the_call_id_budget_binds_across_source_addresses(api, other_ip_api):
    """Two addresses, one platform call id. Vapi hands the same id to every tool
    call in one phone call, so this budget is what a caller cannot shed by
    changing networks mid-call.
    """
    limit = get_settings().max_sessions_per_call_id_per_day
    call_id = "call-abc123"

    for index in range(limit):
        source = api if index % 2 == 0 else other_ip_api
        assert (
            source.post(
                "/tools/create_session", {"consent_given": True}, call_id=call_id
            ).status_code
            == 200
        )

    assert (
        other_ip_api.post(
            "/tools/create_session", {"consent_given": True}, call_id=call_id
        ).status_code
        == 429
    )


def test_a_call_id_the_caller_did_not_sign_is_refused(api, client):
    """The call id is a rate-limit key, so an unsigned one is a key the caller
    picks — which is no key at all. Swapping the header after signing must break
    the signature, not silently open a fresh budget.
    """
    import json
    import time

    from app.security import request_auth

    body = json.dumps({"consent_given": True}).encode()
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    secret = get_settings().channel_secret("web")
    signature = request_auth.sign(secret, timestamp, nonce, body, "call-one")

    response = client.post(
        "/tools/create_session",
        content=body,
        headers={
            "content-type": "application/json",
            "x-vb-channel": "web",
            "x-vb-timestamp": timestamp,
            "x-vb-nonce": nonce,
            "x-vb-signature": signature,
            "x-vb-call-id": "call-two",
        },
    )
    assert response.status_code == 401


# --------------------------------------------------------- booking budgets


def test_the_per_name_cap_refuses_and_is_still_only_the_soft_layer(api, session_id):
    """Both halves of the honest claim in one test.

    The cap refuses a fourth booking under one name, and a different name books
    freely — which is exactly why the spec calls this the soft layer and puts the
    hard backstop somewhere the caller cannot reach.
    """
    limit = get_settings().max_bookings_per_name_per_day
    for ordinal in range(1, limit + 1):
        assert _book(api, session_id, name="Ahmed Khan", slot_ordinal=ordinal).status_code == 200

    refused = _book(api, session_id, name="Ahmed Khan", slot_ordinal=limit + 1)
    assert refused.status_code == 429

    evaded = _book(api, session_id, name="Bilal Shah", slot_ordinal=limit + 1)
    assert evaded.status_code == 200


def test_the_global_cap_degrades_gracefully(api, session_id, db, monkeypatch):
    """The hard backstop refuses new bookings and nothing else.

    A booking flood must not take cancellation down with it: the caller holding a
    reference for an appointment made before the cap was reached still cancels.
    """
    monkeypatch.setattr(get_settings(), "max_bookings_per_day_global", 1)

    first = _book(api, session_id, name="Ahmed Khan", slot_ordinal=1)
    assert first.status_code == 200
    reference = first.json()["reference"]
    day = first.json()["starts_at_local"][:10]

    over = _book(api, session_id, name="Zara Iqbal", slot_ordinal=2)
    assert over.status_code == 429
    assert over.json()["detail"] == rate_limit.RATE_LIMITED_TEXT

    cancelled = api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": day,
            "reference": reference,
        },
    )
    assert cancelled.status_code == 200

    appointment = db.execute(select(Appointment)).scalars().one()
    assert appointment.status == STATUS_CANCELLED


def test_the_global_cap_refuses_every_name_identically(api, session_id, monkeypatch):
    """Once the backstop is spent the per-name cap can no longer be read as a
    signal about anybody else's activity, because every name is refused.
    """
    monkeypatch.setattr(get_settings(), "max_bookings_per_day_global", 1)
    assert _book(api, session_id, name="Ahmed Khan", slot_ordinal=1).status_code == 200

    a = _book(api, session_id, name="Ahmed Khan", slot_ordinal=2)
    b = _book(api, session_id, name="Someone Else", slot_ordinal=2)
    assert a.status_code == b.status_code == 429
    assert a.json() == b.json()


def test_a_lost_slot_race_costs_the_caller_nothing(api, session_id, db):
    """The cap protects booked slots, not attempts. A caller who is beaten to a
    slot has consumed no resource and must not be charged for one.
    """
    first = _book(api, session_id, name="Ahmed Khan", slot_ordinal=1)
    assert first.status_code == 200
    before = _bucket(db, rate_limit.SCOPE_BOOKING_GLOBAL).count

    # The same slot, offered again to a session that still holds the old offer.
    taken = api.post(
        "/tools/book_appointment",
        {
            "session_id": session_id,
            "slot_ordinal": 1,
            "patient_name": "Ahmed Khan",
            "idempotency_key": str(uuid.uuid4()),
        },
    )
    assert taken.status_code == 409

    db.expire_all()
    assert _bucket(db, rate_limit.SCOPE_BOOKING_GLOBAL).count == before


def test_an_idempotent_replay_is_not_a_second_booking(api, session_id, db):
    """F15 says a retry returns the original result. F8 must agree: a network
    timeout the client retried has consumed one slot, so it costs one unit.
    """
    api.post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
    api.post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})
    payload = {
        "session_id": session_id,
        "slot_ordinal": 1,
        "patient_name": "Ahmed Khan",
        "idempotency_key": str(uuid.uuid4()),
    }
    first = api.post("/tools/book_appointment", payload)
    assert first.status_code == 200
    retry = api.post("/tools/book_appointment", payload)
    assert retry.status_code == 200
    assert retry.json()["reference"] == first.json()["reference"]

    db.expire_all()
    assert _bucket(db, rate_limit.SCOPE_BOOKING_GLOBAL).count == 1
    assert len(db.execute(select(Appointment)).scalars().all()) == 1


# ------------------------------------------------------------- persistence


def test_every_budget_is_a_database_row_and_none_is_keyed_on_a_session(
    api, session_id, db
):
    """C-23 in one assertion. A budget in process memory dies with the worker;
    a budget keyed on session_id dies with the reconnect. Neither is a budget.
    """
    _book(api, session_id, name="Ahmed Khan", slot_ordinal=1)
    api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": "2099-01-01",
            "reference": "0000",
        },
    )

    buckets = db.execute(select(RateLimitBucket)).scalars().all()
    scopes = {b.scope for b in buckets}
    assert scopes == {
        rate_limit.SCOPE_SESSION_IP,
        rate_limit.SCOPE_BOOKING_NAME,
        rate_limit.SCOPE_BOOKING_GLOBAL,
        rate_limit.SCOPE_CANCEL_REFERENCE,
    }
    for bucket in buckets:
        assert session_id not in bucket.bucket_key
        # The key is an HMAC because this table is not encrypted and one of the
        # subjects is a patient name.
        assert len(bucket.bucket_key) == 64
        assert "ahmed" not in bucket.bucket_key.lower()


@pytest.mark.parametrize(
    "setting",
    [
        "abuse_window_hours",
        "max_sessions_per_ip_per_day",
        "max_sessions_per_call_id_per_day",
        "max_bookings_per_name_per_day",
        "max_bookings_per_day_global",
        "max_reference_attempts",
        "reference_lock_minutes",
    ],
)
def test_every_limit_is_configuration(setting):
    """F8 acceptance, literally: no threshold is a magic number in a branch."""
    assert isinstance(getattr(get_settings(), setting), int)


def _rate_limit_rows(db) -> list[AuditEvent]:
    return (
        db.execute(select(AuditEvent).where(AuditEvent.action == ACTION_RATE_LIMIT))
        .scalars()
        .all()
    )


def _bucket(db, scope: str) -> RateLimitBucket:
    return (
        db.execute(select(RateLimitBucket).where(RateLimitBucket.scope == scope))
        .scalars()
        .one()
    )
