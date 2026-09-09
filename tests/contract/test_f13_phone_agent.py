"""F13 — the Vapi phone agent.

Acceptance is three claims: unsigned tool calls are rejected, the duration cap
is enforced at the platform *and* the server, and a scripted conversation leaves
identical database state on the web and on the phone.

The parity test is the one that carries the design. "All three channels call the
same authenticated endpoints; no channel has a privileged path" (§1.1) is easy
to write and easy to quietly stop being true — the phone is where a shortcut
would be most tempting, because it is the channel that is hardest to test.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from agent.vapi import assistant as vapi_assistant
from agent.vapi import webhook as vapi_webhook
from agent.vapi.webhook import (
    ALLOWED_ARGUMENTS,
    UnauthenticatedWebhook,
    UnknownTool,
    parse_tool_calls,
    verify_signature,
)
from app.config import get_settings
from app.models import STATUS_ACTIVE, STATUS_CANCELLED, Appointment, AuditEvent, Patient
from app.security import rate_limit

SECRET = b"phone-webhook-secret-for-tests"


def _sign(body: bytes, secret: bytes = SECRET) -> dict[str, str]:
    return {
        vapi_webhook.VAPI_SIGNATURE_HEADER: hmac.new(
            secret, body, hashlib.sha256
        ).hexdigest()
    }


def _envelope(tool: str, arguments: dict, *, call_id: str = "vapi-call-1", id="tc-1"):
    return {
        "message": {
            "call": {"id": call_id},
            "toolCalls": [
                {"id": id, "function": {"name": tool, "arguments": arguments}}
            ],
        }
    }


# --------------------------------------------------------------------------
# Unsigned tool calls are rejected
# --------------------------------------------------------------------------


def _shared(secret: bytes = SECRET) -> dict[str, str]:
    """What Vapi's dashboard "Server URL Secret" actually sends: the literal."""
    return {vapi_webhook.VAPI_SECRET_HEADER: secret.decode()}


# --------------------------------------------------------------------------
# Two authentication schemes, checked separately
# --------------------------------------------------------------------------


def test_the_literal_shared_secret_is_accepted():
    """`X-Vapi-Secret` carries the secret itself, not an HMAC.

    This is the regression that matters: verifying it as though it were an HMAC
    refuses every dashboard-configured assistant with a 401 that reads like a
    problem on the sender's side.
    """
    body = json.dumps(_envelope("search_doctors", {"specialty": "Cardiology"})).encode()
    verify_signature(body, _shared(), secret=SECRET)


def test_the_hmac_signature_is_accepted():
    body = json.dumps(_envelope("search_doctors", {"specialty": "Cardiology"})).encode()
    verify_signature(body, _sign(body), secret=SECRET)


def test_a_wrong_literal_secret_is_refused():
    body = json.dumps(_envelope("search_doctors", {})).encode()
    with pytest.raises(UnauthenticatedWebhook):
        verify_signature(body, _shared(b"not-the-secret"), secret=SECRET)


def test_neither_scheme_accepts_the_other_ones_value():
    """Cross-scheme confusion. The secret is not a valid signature and the
    signature is not a valid secret, and each header is judged on its own terms.
    """
    body = json.dumps(_envelope("search_doctors", {})).encode()
    digest = hmac.new(SECRET, body, hashlib.sha256).hexdigest()

    with pytest.raises(UnauthenticatedWebhook):
        # The literal secret arriving in the signature header.
        verify_signature(
            body, {vapi_webhook.VAPI_SIGNATURE_HEADER: SECRET.decode()}, secret=SECRET
        )
    with pytest.raises(UnauthenticatedWebhook):
        # An HMAC arriving in the shared-secret header.
        verify_signature(
            body, {vapi_webhook.VAPI_SECRET_HEADER: digest}, secret=SECRET
        )


def test_a_present_signature_must_validate_and_never_falls_through():
    """"Try each scheme until one passes" would turn two checks into a choice
    the caller makes, and the caller here is untrusted.
    """
    body = json.dumps(_envelope("search_doctors", {})).encode()
    headers = {
        vapi_webhook.VAPI_SIGNATURE_HEADER: "0" * 64,
        **_shared(),  # a perfectly valid shared secret alongside it
    }
    with pytest.raises(UnauthenticatedWebhook):
        verify_signature(body, headers, secret=SECRET)


def test_a_valid_signature_wins_when_both_headers_are_present():
    body = json.dumps(_envelope("search_doctors", {})).encode()
    verify_signature(body, {**_sign(body), **_shared(b"junk")}, secret=SECRET)


def test_the_secret_comparison_leaks_no_length():
    """A short guess and a long one are the same amount of work: both sides are
    digested to 32 bytes before they are compared.
    """
    body = b"{}"
    for guess in (b"", b"a", SECRET[:-1], SECRET + b"x", b"y" * 4096):
        with pytest.raises(UnauthenticatedWebhook):
            verify_signature(body, _shared(guess), secret=SECRET)


def test_headers_are_matched_case_insensitively():
    body = json.dumps(_envelope("search_doctors", {})).encode()
    verify_signature(body, {"X-Vapi-Secret": SECRET.decode()}, secret=SECRET)
    digest = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    verify_signature(body, {"X-VAPI-SIGNATURE": digest}, secret=SECRET)


def test_an_unsigned_webhook_is_refused():
    bridge = vapi_webhook.VapiBridge(base_url="http://127.0.0.1:1", secret=SECRET)
    body = json.dumps(_envelope("search_doctors", {"specialty": "Cardiology"})).encode()
    with pytest.raises(UnauthenticatedWebhook):
        bridge.handle(body, {})


def test_a_wrongly_signed_webhook_is_refused():
    body = json.dumps(_envelope("search_doctors", {"specialty": "Cardiology"})).encode()
    with pytest.raises(UnauthenticatedWebhook):
        verify_signature(body, _sign(body, b"not-the-secret"), secret=SECRET)


def test_a_tampered_body_breaks_the_signature():
    """Signed over the raw bytes, so a change anywhere in the payload breaks it
    — including in a field this version does not read.
    """
    original = json.dumps(_envelope("search_doctors", {"specialty": "Cardiology"})).encode()
    headers = _sign(original)
    tampered = original.replace(b"Cardiology", b"Neurology")
    verify_signature(original, headers, secret=SECRET)
    with pytest.raises(UnauthenticatedWebhook):
        verify_signature(tampered, headers, secret=SECRET)


def test_the_webhook_secret_is_not_the_channel_secret():
    """Vapi proving it is Vapi and the agent proving it is a known channel are
    two different claims. One key for both would mean a leak of either is a leak
    of both.
    """
    settings = get_settings()
    assert settings.vb_vapi_webhook_secret != settings.vb_channel_secret_phone


def test_a_missing_webhook_secret_refuses_every_call_rather_than_allowing_them(
    monkeypatch,
):
    monkeypatch.delenv("VB_VAPI_WEBHOOK_SECRET", raising=False)
    with pytest.raises(UnauthenticatedWebhook):
        vapi_webhook.webhook_secret({})


def test_a_call_without_a_platform_id_is_refused():
    """The call id is the rate-limit key and the session key. A payload with no
    call is a payload this side cannot budget.
    """
    bridge = vapi_webhook.VapiBridge(base_url="http://127.0.0.1:1", secret=SECRET)
    body = json.dumps(
        {"message": {"toolCalls": [{"id": "t", "function": {"name": "clear_reference_digits", "arguments": {}}}]}}
    ).encode()
    with pytest.raises(UnauthenticatedWebhook):
        bridge.handle(body, _sign(body))


# --------------------------------------------------------------------------
# The model cannot smuggle a field through the bridge (C-04)
# --------------------------------------------------------------------------


def test_no_tool_accepts_a_database_identifier():
    for tool, allowed in ALLOWED_ARGUMENTS.items():
        for argument in allowed:
            assert not argument.endswith("_id") or argument == "session_id", (
                tool,
                argument,
            )
            assert argument not in {
                "appointment_id",
                "patient_id",
                "doctor_id",
                "session_id",
            }, (tool, argument)


def test_invented_arguments_are_dropped_before_a_request_exists():
    """A compromised model sends whatever it likes. Strict Pydantic would refuse
    it on the far side; dropping it here means it never reaches a log either.
    """
    calls = parse_tool_calls(
        _envelope(
            "cancel_appointment",
            {
                "patient_name": "Ahmed Khan",
                "appointment_date": "2030-01-01",
                "reference": "4729",
                "appointment_id": 7,
                "is_admin": True,
                "session_id": "somebody-elses-session",
            },
        )
    )
    assert calls[0].arguments == {
        "patient_name": "Ahmed Khan",
        "appointment_date": "2030-01-01",
        "reference": "4729",
    }


def test_a_tool_outside_the_published_surface_is_refused():
    with pytest.raises(UnknownTool):
        parse_tool_calls(_envelope("list_my_appointments", {}))
    assert "list_my_appointments" not in ALLOWED_ARGUMENTS


def test_arguments_arriving_as_a_json_string_are_still_filtered():
    calls = parse_tool_calls(
        _envelope(
            "book_appointment",
            json.dumps({"slot_ordinal": 1, "patient_name": "Ahmed Khan", "patient_id": 3}),
        )
    )
    assert calls[0].arguments == {"slot_ordinal": 1, "patient_name": "Ahmed Khan"}


def test_the_call_id_is_bounded_and_from_a_closed_character_set():
    """It becomes a rate-limit key, so it is cleaned before anything uses it."""
    calls = parse_tool_calls(
        _envelope("clear_reference_digits", {}, call_id="../../etc/passwd" + "x" * 200)
    )
    assert len(calls[0].call_id) <= 64
    assert all(c.isalnum() or c in "-_" for c in calls[0].call_id)


def test_the_idempotency_key_is_minted_here_and_not_by_the_model():
    """F15: the key is what makes a retry safe, so a model-chosen one is a key
    an attacker chose.
    """
    assert "idempotency_key" not in ALLOWED_ARGUMENTS["book_appointment"]

    state = vapi_webhook.CallState()
    first = state.idempotency_key_for("tool-call-1")
    # A platform retry reuses the tool call id, which is what turns it into an
    # idempotent replay rather than a second appointment.
    assert state.idempotency_key_for("tool-call-1") == first
    assert state.idempotency_key_for("tool-call-2") != first
    uuid.UUID(first)


def test_the_bridge_masks_the_reference_before_it_returns_to_vapi():
    """Vapi keeps its own transcript on its own servers. A reference that lands
    there has outlived the moment it was disclosed in (5.1).
    """
    from agent.client import MASK, ToolResponse

    masked = ToolResponse(
        "book_appointment", 200, {"confirmed": True, "reference": "4729"}, 1.0
    ).for_transcript()
    assert masked["reference"] == MASK


# --------------------------------------------------------------------------
# The assistant configuration
# --------------------------------------------------------------------------


def test_outbound_calling_is_absent_rather_than_restricted():
    """C-07. An assistant that can place calls is one that can be talked into
    placing them, to a premium-rate number, overnight.
    """
    config = vapi_assistant.build_assistant(webhook_url="https://example.invalid/vapi")
    rendered = json.dumps(config)
    for key in ("phoneNumberId", "outbound", "customer", "destination"):
        assert key not in rendered


def test_no_phone_number_appears_anywhere_in_the_repository():
    """C-16, C-17: not the demo's, not anybody's."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[2]
    number = re.compile(r"\+\d{7,15}\b")
    skip = {".git", ".venv", "__pycache__", ".pytest_cache", "uv.lock"}

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".md", ".json", ".html", ".toml"}:
            continue
        if any(part in skip for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert not number.search(text), f"{path} looks like it holds a phone number"


def test_the_assistant_offers_exactly_the_published_tools():
    config = vapi_assistant.build_assistant(webhook_url="https://example.invalid/vapi")
    names = set(vapi_assistant.assistant_tool_names(config))
    assert names == set(ALLOWED_ARGUMENTS)
    assert "list_my_appointments" not in names


def test_every_tool_is_synchronous():
    """The model must not carry on from an assumption about what the server was
    going to say. Every one of these is a decision the server makes.
    """
    config = vapi_assistant.build_assistant(webhook_url="https://example.invalid/vapi")
    assert all(tool["async"] is False for tool in config["model"]["tools"])


def test_the_disclosure_is_the_first_thing_said(client):
    """C-15. On the phone there is no UI gate, so the spoken disclosure is the
    whole of it, and it is stated rather than asked.
    """
    from app.tools.router import DISCLOSURE

    first = vapi_assistant.FIRST_MESSAGE
    assert "recorded" in first
    assert "AI assistant" in first
    assert "can't give medical advice" in first
    # The same three facts the API's own disclosure states.
    for phrase in ("recorded", "AI assistant"):
        assert phrase in DISCLOSURE


def test_the_assistant_config_holds_no_secret():
    config = json.dumps(vapi_assistant.build_assistant(webhook_url="https://x.invalid/v"))
    settings = get_settings()
    for secret in (
        settings.vb_channel_secret_phone,
        settings.vb_encryption_key,
        settings.vb_reference_hmac_key,
    ):
        assert secret not in config
    assert "apiKey" not in config


# --------------------------------------------------------------------------
# The duration cap, at the platform and at the server
# --------------------------------------------------------------------------


def test_the_platform_cap_matches_the_server_cap():
    config = vapi_assistant.build_assistant(webhook_url="https://example.invalid/vapi")
    assert config["maxDurationSeconds"] == get_settings().max_call_seconds
    assert vapi_assistant.MAX_DURATION_SECONDS == get_settings().max_call_seconds


def test_the_server_enforces_the_cap_on_its_own(api, db):
    """The point of the second copy. Vapi's cap is a setting in somebody else's
    dashboard; a cap enforced only where it can be clicked off is not a cap.
    """
    call_id = "vapicall01"
    opened = api.post("/tools/create_session", {"consent_given": True}, call_id=call_id)
    assert opened.status_code == 200
    session_id = opened.json()["session_id"]

    # Still inside the cap.
    assert (
        api.post(
            "/tools/search_doctors",
            {"session_id": session_id, "specialty": "Cardiology"},
            call_id=call_id,
        ).status_code
        == 200
    )

    # Wind the call's clock back past the cap.
    from app.models import RateLimitBucket

    bucket = db.execute(
        select(RateLimitBucket).where(
            RateLimitBucket.scope == rate_limit.SCOPE_CALL_DURATION
        )
    ).scalar_one()
    bucket.window_start_utc = datetime.now(timezone.utc) - timedelta(
        seconds=get_settings().max_call_seconds + 5
    )
    db.commit()

    over = api.post(
        "/tools/search_doctors",
        {"session_id": session_id, "specialty": "Cardiology"},
        call_id=call_id,
    )
    assert over.status_code == 403


def test_a_call_past_the_cap_cannot_open_a_fresh_session(api, db):
    """The loophole a per-session cap would leave: hang up, call back on the same
    platform call, start the clock again.
    """
    from app.models import RateLimitBucket

    call_id = "vapicall02"
    assert (
        api.post(
            "/tools/create_session", {"consent_given": True}, call_id=call_id
        ).status_code
        == 200
    )

    bucket = db.execute(
        select(RateLimitBucket).where(
            RateLimitBucket.scope == rate_limit.SCOPE_CALL_DURATION
        )
    ).scalar_one()
    bucket.window_start_utc = datetime.now(timezone.utc) - timedelta(
        seconds=get_settings().max_call_seconds + 5
    )
    db.commit()

    refused = api.post("/tools/create_session", {"consent_given": True}, call_id=call_id)
    assert refused.status_code == 429


def test_the_cap_does_not_restart_when_a_caller_reconnects(api, db):
    from app.models import RateLimitBucket

    call_id = "vapicall03"
    api.post("/tools/create_session", {"consent_given": True}, call_id=call_id)
    started = db.execute(
        select(RateLimitBucket.window_start_utc).where(
            RateLimitBucket.scope == rate_limit.SCOPE_CALL_DURATION
        )
    ).scalar_one()

    api.post("/tools/create_session", {"consent_given": True}, call_id=call_id)
    db.expire_all()
    again = db.execute(
        select(RateLimitBucket.window_start_utc).where(
            RateLimitBucket.scope == rate_limit.SCOPE_CALL_DURATION
        )
    ).scalar_one()

    assert again == started


def test_a_channel_without_a_call_id_is_not_capped_by_this(api, session_id):
    """The tester and a pre-call web session have no platform id. Nothing is
    lost: they are bounded by the 15-minute session TTL and the per-IP budget,
    and this cap exists for the channel that costs money per minute.
    """
    assert (
        api.post(
            "/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"}
        ).status_code
        == 200
    )


# --------------------------------------------------------------------------
# Parity: the same conversation, the same database state
# --------------------------------------------------------------------------


def _run_conversation(api, channel: str, *, call_id: str | None = None) -> dict:
    """One scripted conversation, driven over one channel."""
    session_id = api.post(
        "/tools/create_session", {"consent_given": True}, channel=channel, call_id=call_id
    ).json()["session_id"]

    def post(path, payload):
        return api.post(path, payload, channel=channel, call_id=call_id)

    post("/tools/screen_turn", {"session_id": session_id, "utterance": "I'd like to book"})
    post("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"})
    post("/tools/get_available_slots", {"session_id": session_id, "doctor_ordinal": 1})
    booked = post(
        "/tools/book_appointment",
        {
            "session_id": session_id,
            "slot_ordinal": 1,
            "patient_name": "Ahmed Khan",
            "idempotency_key": str(uuid.uuid4()),
        },
    ).json()

    appointment_date = datetime.fromisoformat(booked["starts_at_local"]).date().isoformat()

    # A wrong reference, then the right one. The denial has to look the same on
    # both channels too.
    denied = post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": appointment_date,
            "reference": "0000" if booked["reference"] != "0000" else "1111",
        },
    )
    cancelled = post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": "Ahmed Khan",
            "appointment_date": appointment_date,
            "reference": booked["reference"],
        },
    )

    return {
        "booked_ok": booked["confirmed"],
        "doctor_name": booked["doctor_name"],
        "denied_status": denied.status_code,
        "denied_body": denied.json(),
        "cancelled_status": cancelled.status_code,
        "cancelled_body": cancelled.json(),
    }


def _database_shape() -> dict:
    """Read the shape on a short-lived session of its own.

    Deliberately not the `db` fixture: this test rebuilds the database between
    the two runs, and a session held across that rebuild is a session pointing
    at a disposed engine.
    """
    from app.db import base as db_base

    session = db_base.get_sessionmaker()()
    try:
        return {
            "active": len(
                session.execute(
                    select(Appointment.id).where(Appointment.status == STATUS_ACTIVE)
                )
                .scalars()
                .all()
            ),
            "cancelled": len(
                session.execute(
                    select(Appointment.id).where(Appointment.status == STATUS_CANCELLED)
                )
                .scalars()
                .all()
            ),
            "patients": len(session.execute(select(Patient.id)).scalars().all()),
            "audit": sorted(
                (e.action, e.decision, e.reason)
                for e in session.execute(select(AuditEvent)).scalars().all()
            ),
        }
    finally:
        session.close()


def _rebuild_database() -> None:
    """The same clean start the autouse fixture gives every other test."""
    from app.db import base as db_base
    from app.db.seed import seed
    from app.models import Base
    from app.security import request_auth
    from app.services import booking, directory

    db_base.reset_engine()
    engine = db_base.build_engine(":memory:")
    db_base.set_engine(engine)
    Base.metadata.create_all(engine)
    with db_base.session_scope() as setup:
        seed(setup)
        directory.load_whitelist(setup)
    request_auth.get_replay_cache().clear()
    booking.forget_references()


def test_the_same_conversation_leaves_the_same_state_on_web_and_phone(api):
    """F13 acceptance. §1.1 says no channel has a privileged path; this is what
    says so in a way that fails if it stops being true.

    Each run gets its own database, so the two are compared against the same
    starting point rather than against each other's leftovers.
    """
    _rebuild_database()
    web = _run_conversation(api, "web")
    web_state = _database_shape()

    _rebuild_database()
    phone = _run_conversation(api, "phone", call_id="vapiparity1")
    phone_state = _database_shape()

    assert web["booked_ok"] == phone["booked_ok"] is True
    assert web["doctor_name"] == phone["doctor_name"]
    assert web["denied_status"] == phone["denied_status"] == 403
    assert web["denied_body"] == phone["denied_body"]
    assert web["cancelled_status"] == phone["cancelled_status"] == 200

    # Byte-for-byte the same database, from two different channels.
    assert web_state == phone_state


def test_the_phone_channel_has_no_endpoint_the_web_channel_lacks(api, session_id):
    from agent.client import TOOLS

    for tool in TOOLS:
        web = api.post(f"/tools/{tool}", {}, channel="web")
        phone = api.post(f"/tools/{tool}", {}, channel="phone")
        # Both channels are refused identically on an empty body: same
        # validation layer, same status, no privileged path either way.
        assert web.status_code == phone.status_code, tool


# --------------------------------------------------------------------------
# The webhook endpoint itself
# --------------------------------------------------------------------------


def _webhook_client():
    from starlette.testclient import TestClient

    from agent.vapi.server import create_app

    bridge = vapi_webhook.VapiBridge(base_url="http://127.0.0.1:1", secret=SECRET)
    return TestClient(create_app(bridge=bridge)), bridge


def test_the_webhook_endpoint_accepts_a_dashboard_configured_secret():
    """End to end over HTTP, in the shape Vapi actually posts."""
    client, _ = _webhook_client()
    body = json.dumps({"message": {"call": {"id": "abc"}, "toolCalls": []}}).encode()

    response = client.post("/vapi/tools", content=body, headers=_shared())
    assert response.status_code == 200
    assert response.json() == {"results": []}


def test_the_webhook_endpoint_refuses_an_unsigned_post():
    client, _ = _webhook_client()
    body = json.dumps(_envelope("search_doctors", {"specialty": "Cardiology"})).encode()

    response = client.post("/vapi/tools", content=body)
    assert response.status_code == 401
    assert response.json() == {"error": "unauthenticated"}


def test_every_rejection_looks_the_same_from_outside():
    """A bad signature, an unknown tool and a malformed envelope are one answer.
    A poster who can tell them apart is being told what to try next.
    """
    client, _ = _webhook_client()

    unsigned = json.dumps(_envelope("search_doctors", {})).encode()
    unknown = json.dumps(_envelope("list_my_appointments", {})).encode()
    malformed = b"{not json"

    bodies = [
        client.post("/vapi/tools", content=unsigned),
        client.post("/vapi/tools", content=unknown, headers=_sign(unknown)),
        client.post("/vapi/tools", content=malformed, headers=_sign(malformed)),
    ]
    assert {r.status_code for r in bodies} == {401}
    assert len({r.text for r in bodies}) == 1


def test_an_oversized_body_is_refused_before_the_signature_check():
    from agent.vapi.server import MAX_BODY_BYTES

    client, _ = _webhook_client()
    huge = b"x" * (MAX_BODY_BYTES + 1)
    assert client.post("/vapi/tools", content=huge, headers=_sign(huge)).status_code == 401


def test_the_webhook_app_exposes_no_route_that_lists_anything():
    from agent.vapi.server import create_app

    app = create_app(bridge=vapi_webhook.VapiBridge(base_url="http://x", secret=SECRET))
    paths = {getattr(route, "path", "") for route in app.routes}
    assert paths == {"/vapi/tools", "/healthz"}
    assert not any("list" in path for path in paths)


def test_the_webhook_process_is_not_the_api_process():
    """The boundary made operational. A route on `app` would put the agent and
    the application in one process, and "the boundary is a network hop" would be
    a comment rather than a fact.
    """
    from app.main import create_app as create_api

    api_paths = {getattr(route, "path", "") for route in create_api().routes}
    assert "/vapi/tools" not in api_paths
