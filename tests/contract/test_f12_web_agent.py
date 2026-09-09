"""F12 — the Pipecat web agent (C-19, C-27).

Acceptance is four claims: no provider key reaches any client bundle, a
mid-sentence interruption is handled cleanly, a reconnection resets no budget,
and the import-boundary check is green.

None of them needs a microphone, and that is deliberate. The audio path is the
part a test suite cannot assert anything useful about; everything that decides
what the system does is a pure function over a configuration or a request to the
API, and all of it is here.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agent import turn, vad
from agent.client import TOOLS, MissingSecret, ToolClient, UnknownTool
from agent.pipecat import PROVIDER_KEY_VARIABLES, PipelineConfig
from agent.pipecat.pipeline import PipecatUnavailable, build_pipeline, tool_client_for
from app.config import get_settings
from app.services.state_machine import State
from app.web import tokens

ROOT = Path(__file__).resolve().parents[2]
WEB_BUNDLE = ROOT / "agent" / "pipecat" / "web" / "index.html"


# --------------------------------------------------------------------------
# State-dependent VAD (C-18)
# --------------------------------------------------------------------------


def test_the_default_threshold_is_seven_hundred_milliseconds():
    assert vad.silence_ms_for(State.INTENT.value) == 700
    assert vad.silence_ms_for(State.SLOT_SELECT.value) == 700


def test_collecting_digits_raises_the_threshold_to_twelve_hundred():
    """People pause between pairs of digits, and that pause looks exactly like a
    finished turn.
    """
    assert vad.silence_ms_for(State.CANCEL_COLLECT_REFERENCE.value) == 1200
    assert vad.silence_ms_for(State.CANCEL_CONFIRM.value) == 1200


def test_the_thresholds_match_the_values_the_browser_is_served():
    """`app/` must never import `agent/`, so the numbers live in config and the
    policy lives here. This is what stops the two drifting apart.
    """
    settings = get_settings()
    assert vad.DEFAULT_SILENCE_MS == settings.vad_default_silence_ms
    assert vad.DIGIT_SILENCE_MS == settings.vad_digit_silence_ms


def test_every_digit_state_is_a_real_state_in_the_machine():
    """The names are duplicated across the boundary rather than imported. This
    is the assertion that keeps a duplicate honest.
    """
    machine = {member.value for member in State}
    assert vad.DIGIT_STATES <= machine


def test_barge_in_stays_on_while_digits_are_being_collected():
    """The case that matters most: a caller correcting a wrong readback must be
    able to cut the agent off mid-sentence.
    """
    profile = vad.profile_for(State.CANCEL_COLLECT_REFERENCE.value)
    assert profile.collecting_digits is True
    assert profile.allow_interruption is True


# --------------------------------------------------------------------------
# Interruption (F12 acceptance: handled cleanly)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", [s.value for s in State])
def test_an_interruption_cancels_speech_and_nothing_else(state):
    """The tempting bug is to "helpfully" clear the digit buffer on a barge-in,
    which throws away digits the caller has already said. The buffer is
    server-side precisely so a cut turn costs nothing (C-18).
    """
    reaction = turn.on_interruption(state)
    assert reaction.cancel_pending_speech is True
    assert reaction.clear_digit_buffer is False
    assert reaction.end_session is False


def test_a_mid_number_cut_loses_no_digits(api, session_id):
    """The interruption case, driven through the API the way a call would.

    Two fragments arriving as two turns is exactly what a badly timed VAD
    boundary produces, and the buffer joins them.
    """
    first = api.post(
        "/tools/append_reference_digits", {"session_id": session_id, "fragment": "47"}
    ).json()
    assert first == {
        "digits_collected": 2,
        "ready": False,
        "readback": None,
        "retries_exhausted": False,
    }

    second = api.post(
        "/tools/append_reference_digits", {"session_id": session_id, "fragment": "29"}
    ).json()
    assert second["digits_collected"] == 4
    assert second["ready"] is True
    assert second["readback"] == "4-7-2-9"


# --------------------------------------------------------------------------
# The turn order — the safety pre-filter is not the model's to skip
# --------------------------------------------------------------------------


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.screened: list[str] = []

    def screen(self, utterance):
        self.screened.append(utterance)
        return self._response


def _response(status_code=200, body=None):
    from agent.client import ToolResponse

    return ToolResponse(
        tool="screen_turn", status_code=status_code, body=body or {}, latency_ms=1.0
    )


def test_an_escalation_ends_the_call_with_the_servers_own_words():
    reply = "This sounds like a medical emergency..."
    plan = turn.screen_turn(
        _FakeClient(_response(body={"escalated": True, "reply": reply})), "chest pain"
    )
    assert plan.disposition is turn.Disposition.SPEAK_AND_END
    assert plan.utterance == reply
    assert plan.model_may_run is False


def test_a_blocked_turn_stops_the_model_and_says_the_servers_words():
    reply = "I'm not able to discuss medical matters..."
    plan = turn.screen_turn(
        _FakeClient(_response(body={"blocks_flow": True, "reply": reply})), "fever"
    )
    assert plan.disposition is turn.Disposition.SPEAK_AND_STOP
    assert plan.utterance == reply
    assert plan.model_may_run is False


def test_an_unreachable_api_stops_the_turn_rather_than_proceeding_unscreened():
    """C-30. The deterministic safety layer lives server-side, so an unreachable
    server means the agent cannot screen. Proceeding would be running the
    booking flow with the emergency filter switched off.
    """
    plan = turn.screen_turn(_FakeClient(_response(status_code=0)), "chest pain")
    assert plan.disposition is turn.Disposition.SPEAK_AND_STOP
    assert plan.utterance == turn.PROVIDER_FAILURE_UTTERANCE
    assert plan.model_may_run is False


def test_a_clear_turn_lets_the_model_run():
    plan = turn.screen_turn(
        _FakeClient(_response(body={"verdict": "clear", "state": "INTENT"})),
        "I'd like to book",
    )
    assert plan.model_may_run is True
    assert plan.utterance is None


@pytest.mark.parametrize(
    "status,expected",
    [
        (0, turn.PROVIDER_FAILURE_UTTERANCE),
        (401, turn.UNIFORM_REFUSAL_UTTERANCE),
        (403, turn.UNIFORM_REFUSAL_UTTERANCE),
        (429, turn.RATE_LIMITED_UTTERANCE),
        (500, turn.PROVIDER_FAILURE_UTTERANCE),
    ],
)
def test_a_failed_tool_call_has_one_fixed_thing_to_say(status, expected):
    """The agent never composes a failure message. A 401 and a 403 say the same
    thing as each other, because a caller who can tell them apart has learned
    something about which of their fields was wrong (6.2).
    """
    from agent.client import ToolResponse

    response = ToolResponse(
        tool="cancel_appointment", status_code=status, body={}, latency_ms=1.0
    )
    assert turn.utterance_for(response) == expected


def test_a_successful_call_has_no_fixed_utterance():
    from agent.client import ToolResponse

    response = ToolResponse("book_appointment", 200, {"confirmed": True}, 1.0)
    assert turn.utterance_for(response) is None


# --------------------------------------------------------------------------
# Room tokens (server-minted, 60 seconds, room-scoped)
# --------------------------------------------------------------------------


def test_a_room_token_lasts_sixty_seconds():
    minted = tokens.mint(now=1_000_000)
    assert minted.expires_at == 1_000_060
    assert tokens.verify(minted.token, now=1_000_059).room == minted.room


def test_an_expired_room_token_is_refused():
    minted = tokens.mint(now=1_000_000)
    with pytest.raises(tokens.InvalidRoomToken):
        tokens.verify(minted.token, now=1_000_060)


def test_a_token_for_one_room_does_not_open_another():
    """"Room-scoped" is the whole claim. Verifying the signature alone would
    accept a valid token for room A as entry to room B.
    """
    minted = tokens.mint("room-a")
    assert tokens.verify(minted.token, room="room-a").room == "room-a"
    with pytest.raises(tokens.InvalidRoomToken):
        tokens.verify(minted.token, room="room-b")


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t[:-1] + ("a" if t[-1] != "a" else "b"),
        lambda t: t.replace(".", ".x", 1),
        lambda t: t.split(".", 1)[0],
        lambda t: "not-a-token",
        lambda t: "",
    ],
)
def test_a_tampered_token_is_refused_and_says_nothing_about_why(mangle):
    minted = tokens.mint()
    with pytest.raises(tokens.InvalidRoomToken):
        tokens.verify(mangle(minted.token))


def test_room_ids_are_unguessable():
    ids = {tokens.new_room_id() for _ in range(200)}
    assert len(ids) == 200
    assert all(len(room) >= 20 for room in ids)


def test_the_mint_endpoint_hands_the_browser_a_room_and_a_token(client):
    response = client.post("/web/room-token")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"room", "token", "expires_in_seconds"}
    assert 0 < body["expires_in_seconds"] <= 60
    assert tokens.verify(body["token"], room=body["room"]).room == body["room"]


def test_the_mint_endpoint_is_budgeted(client):
    """It is the one unauthenticated POST in the system. Unbudgeted, it is a
    free token generator, which is the web half of C-07.
    """
    limit = get_settings().max_room_tokens_per_ip_per_day
    for _ in range(limit):
        assert client.post("/web/room-token").status_code == 200
    refused = client.post("/web/room-token")
    assert refused.status_code == 429
    assert "try again later" in refused.json()["detail"]


def test_the_mint_endpoint_does_not_spend_the_call_budget(client, api):
    """A legitimate mint-then-connect must not cost a caller two of their three
    daily calls.
    """
    assert client.post("/web/room-token").status_code == 200
    for _ in range(get_settings().max_sessions_per_ip_per_day):
        assert api.post("/tools/create_session", {"consent_given": True}).status_code == 200


def test_the_web_config_carries_no_secret(client):
    response = client.post("/web/room-token")
    assert response.status_code == 200

    config = client.get("/web/config")
    assert config.status_code == 200
    body = config.json()
    assert set(body) == {
        "consent_required",
        "disclosure",
        "emergency_service",
        "emergency_number",
        "default_silence_ms",
        "digit_silence_ms",
    }
    assert body["consent_required"] is True
    settings = get_settings()
    for secret in (
        settings.vb_channel_secret_web,
        settings.vb_room_token_key,
        settings.vb_encryption_key,
    ):
        assert secret not in config.text


# --------------------------------------------------------------------------
# No provider key in any client bundle (build-time grep)
# --------------------------------------------------------------------------


def test_the_client_bundle_check_passes():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_client_bundle.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_client_bundle_check_actually_catches_a_planted_key(tmp_path, monkeypatch):
    """A guard nobody has watched fail is a guard nobody knows works."""
    import importlib

    module = importlib.import_module("scripts.check_client_bundle")

    planted = tmp_path / "leak.html"
    planted.write_text(
        '<script>const key = "gsk_abcdefghijklmnopqrstuvwxyz012345";</script>',
        encoding="utf-8",
    )
    assert module.scan(planted)

    named = tmp_path / "named.js"
    named.write_text("// TODO: read DEEPGRAM_API_KEY here\n", encoding="utf-8")
    assert module.scan(named)


def test_the_browser_bundle_names_no_credential():
    source = WEB_BUNDLE.read_text(encoding="utf-8")
    for name in PROVIDER_KEY_VARIABLES:
        assert name not in source
    assert "VB_CHANNEL_SECRET" not in source


def test_the_browser_bundle_gates_the_microphone_behind_consent():
    """C-27: a spoken disclosure is not consent on the web, because by the time
    it is spoken the microphone is already live.
    """
    source = WEB_BUNDLE.read_text(encoding="utf-8")
    # Call sites, not mentions: the file talks about `getUserMedia` in two
    # comments explaining why there is exactly one of these.
    assert source.count("getUserMedia(") == 1

    before, _after = source.split("getUserMedia(", 1)
    # The one call sits inside the start button's handler, behind the checkbox.
    assert 'start.addEventListener("click"' in before
    assert "if (!consent.checked) return;" in before


def test_the_pipeline_config_hands_the_browser_only_a_room_and_a_token():
    config = PipelineConfig(
        room="room-1", room_token="tok", base_url="http://localhost:8000"
    )
    assert config.as_client_payload() == {"room": "room-1", "token": "tok"}


def test_the_pipeline_config_holds_no_secret():
    config = PipelineConfig(room="r", room_token="t", base_url="http://localhost")
    rendered = repr(config)
    for name in PROVIDER_KEY_VARIABLES:
        assert name not in rendered


def test_building_a_live_pipeline_without_the_audio_stack_fails_loudly():
    config = PipelineConfig(room="r", room_token="t", base_url="http://localhost")
    with pytest.raises(PipecatUnavailable):
        build_pipeline(config)


# --------------------------------------------------------------------------
# Reconnection resets no budget (C-23)
# --------------------------------------------------------------------------


def test_a_reconnection_resets_no_budget(api, app):
    """Budgets key on the source address and the signed call id, never on
    session_id — which is precisely the value a reconnect refreshes.
    """
    call_id = "room-abc123"
    limit = get_settings().max_sessions_per_call_id_per_day

    for _ in range(limit):
        assert (
            api.post(
                "/tools/create_session", {"consent_given": True}, call_id=call_id
            ).status_code
            == 200
        )

    # The caller reconnects: brand new session, same call.
    reconnected = api.post(
        "/tools/create_session", {"consent_given": True}, call_id=call_id
    )
    assert reconnected.status_code == 429


def test_the_web_call_id_is_the_room_so_a_reconnect_keeps_its_budget(monkeypatch):
    """The room id is server-minted, unguessable and stable across a reconnect,
    which is exactly what a rate-limit key has to be.
    """
    monkeypatch.setenv("VB_CHANNEL_SECRET_WEB", "AAAA" * 11)
    config = PipelineConfig(room="room-xyz", room_token="t", base_url="http://x")
    client = tool_client_for(config)
    assert client.call_id == "room-xyz"
    assert client.channel == "web"


# --------------------------------------------------------------------------
# The boundary
# --------------------------------------------------------------------------


def test_the_import_boundary_check_covers_the_agent_package():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_import_boundary.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "agent" in result.stdout


def test_nothing_under_agent_imports_the_service_layer():
    forbidden = ("app.services", "app.db", "app.models", "app.security", "app.tools")
    for path in sorted((ROOT / "agent").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for module in forbidden:
            assert f"import {module}" not in source, path
            assert f"from {module}" not in source, path


def test_the_agent_cannot_call_a_tool_that_is_not_published(monkeypatch):
    monkeypatch.setenv("VB_CHANNEL_SECRET_WEB", "AAAA" * 11)
    client = ToolClient(channel="web", base_url="http://127.0.0.1:1")
    with pytest.raises(UnknownTool):
        client.call("list_my_appointments", session_id="x")
    assert "list_my_appointments" not in TOOLS


def test_the_agent_refuses_to_start_without_its_channel_secret(monkeypatch):
    monkeypatch.delenv("VB_CHANNEL_SECRET_WEB", raising=False)
    with pytest.raises(MissingSecret):
        ToolClient(channel="web", base_url="http://127.0.0.1:1")


def test_an_unreachable_api_is_an_outcome_and_not_a_crash(monkeypatch):
    """C-30. A tester or an agent that dies with a stack trace when the server
    is down teaches nothing about the failure it exists to model.
    """
    monkeypatch.setenv("VB_CHANNEL_SECRET_WEB", "AAAA" * 11)
    client = ToolClient(channel="web", base_url="http://127.0.0.1:1", timeout_seconds=0.2)
    response = client.call("search_doctors", session_id="x" * 12, specialty="Cardiology")
    assert response.status_code == 0
    assert response.reachable is False
    assert response.ok is False


def test_the_reference_is_masked_before_it_reaches_a_transcript():
    from agent.client import MASK, ToolResponse

    response = ToolResponse(
        "book_appointment",
        200,
        {"confirmed": True, "reference": "4729", "doctor_name": "Dr. X"},
        1.0,
    )
    masked = response.for_transcript()
    assert masked["reference"] == MASK
    assert "4729" not in str(masked)
    assert masked["doctor_name"] == "Dr. X"
