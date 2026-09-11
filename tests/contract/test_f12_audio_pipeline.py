"""F12 — the audio path's decisions, asserted without an audio path.

Every test here runs on a machine with no Pipecat, no Silero, no provider key
and no microphone, which is the whole design of `agent/pipecat/`. What a test
suite can say about a live WebRTC call is almost nothing; what it can say about
*what the pipeline decides* is everything, so the deciding parts are pure
functions and they are all here:

* `screen.action_for` — what happens to a turn the server screened out;
* `pipeline.PIPELINE_ORDER` — where the screen sits relative to the model;
* `pipeline.required_provider_keys` — what the demo actually needs to start;
* the browser page — that it still gates the microphone and still talks to one
  origin, now that it has a transport in it.

What is *not* covered, said plainly rather than implied: `build_pipeline`,
`start_call` and `run_call` are calls into Pipecat's runtime. They are marked
`pragma: no cover` and they are unverified until the voice group is installed
and somebody speaks into a microphone.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from agent.pipecat import pipeline
from agent.pipecat.pipeline import (
    PIPELINE_ORDER,
    PipecatUnavailable,
    PipelineConfig,
    build_pipeline,
    missing_provider_keys,
    required_provider_keys,
)
from agent.pipecat.screen import ScreenAction, action_for
from agent.turn import Disposition, TurnPlan

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "agent" / "pipecat" / "web" / "index.html"


# --------------------------------------------------------------------------
# The screen's verdict is obeyed, not weighed (F10, C-30)
# --------------------------------------------------------------------------


def test_a_clear_turn_is_the_only_one_the_model_sees():
    action = action_for(TurnPlan(Disposition.PROCEED, state="INTENT"))
    assert action == ScreenAction(forward_to_model=True)


def test_a_blocked_turn_never_reaches_the_model():
    """The model gets no turn in which to be talked round. Medical advice and
    volunteered symptoms are refused in the server's words, and the content is
    not acknowledged (6.3).
    """
    action = action_for(TurnPlan(Disposition.SPEAK_AND_STOP, "I can't advise on that."))
    assert action.silences_the_model
    assert action.speak == "I can't advise on that."
    assert action.end_call is False


def test_an_escalation_ends_the_call_and_the_model_never_ran():
    action = action_for(
        TurnPlan(Disposition.SPEAK_AND_END, "Please call 1122.", escalated=True)
    )
    assert action.silences_the_model
    assert action.speak == "Please call 1122."
    assert action.end_call is True


def test_an_unknown_disposition_does_not_default_to_letting_the_model_run():
    """The failure mode that matters. A disposition added later and not handled
    here must fall to the safe side, not to "forward it".
    """

    class _Future(str):
        pass

    action = action_for(TurnPlan(_Future("something_new"), "…"))
    assert action.silences_the_model


@pytest.mark.parametrize(
    "plan",
    [
        TurnPlan(Disposition.SPEAK_AND_STOP, "x"),
        TurnPlan(Disposition.SPEAK_AND_END, "x"),
    ],
)
def test_nothing_but_proceed_forwards_a_turn(plan):
    assert action_for(plan).forward_to_model is False


# --------------------------------------------------------------------------
# Where the screen sits is the mechanism (C-19)
# --------------------------------------------------------------------------


def test_the_screen_runs_before_the_model():
    assert PIPELINE_ORDER.index("screen") < PIPELINE_ORDER.index("llm")


def test_the_screen_runs_after_the_transcriber_and_before_the_context():
    """Any later and it would be filtering what the model already saw, which is
    not filtering.
    """
    assert PIPELINE_ORDER.index("stt") < PIPELINE_ORDER.index("screen")
    assert PIPELINE_ORDER.index("screen") < PIPELINE_ORDER.index("context.user")


def test_speech_is_synthesised_after_the_model_and_before_the_transport():
    assert PIPELINE_ORDER.index("llm") < PIPELINE_ORDER.index("tts")
    assert PIPELINE_ORDER.index("tts") < PIPELINE_ORDER.index("transport.output")


# --------------------------------------------------------------------------
# One key runs the demo (spec §1.2)
# --------------------------------------------------------------------------


def test_the_default_build_needs_one_provider_key():
    """Silero, Piper and SmallWebRTC need no account — that is why they were
    chosen — and Groq serves the LLM and Whisper both.
    """
    assert required_provider_keys(PipelineConfig(room="", room_token="", base_url="")) == (
        "GROQ_API_KEY",
    )


def test_choosing_deepgram_asks_for_deepgram_and_nothing_else():
    config = PipelineConfig(room="", room_token="", base_url="", stt="deepgram")
    assert required_provider_keys(config) == ("DEEPGRAM_API_KEY", "GROQ_API_KEY")


def test_no_unused_provider_is_demanded(monkeypatch):
    """The bug this replaced: `missing_provider_keys` returned all six names in
    `PROVIDER_KEY_VARIABLES`, so a correctly configured demo refused to start
    unless you had also signed up for ElevenLabs, Cartesia, OpenAI and Daily.
    """
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    for unused in ("ELEVENLABS_API_KEY", "CARTESIA_API_KEY", "OPENAI_API_KEY", "DAILY_API_KEY"):
        monkeypatch.delenv(unused, raising=False)
    monkeypatch.delenv("DEEPGRAM_API_KEY", raising=False)

    assert missing_provider_keys(PipelineConfig(room="", room_token="", base_url="")) == ()


def test_a_missing_key_is_still_named(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert missing_provider_keys(
        PipelineConfig(room="", room_token="", base_url="")
    ) == ("GROQ_API_KEY",)


def test_the_forbidden_list_is_still_every_name_a_browser_must_not_see():
    """`PROVIDER_KEY_VARIABLES` keeps its job — it is the list the client-bundle
    check greps for — and is no longer mistaken for a list of requirements.
    """
    assert "GROQ_API_KEY" in pipeline.PROVIDER_KEY_VARIABLES
    assert "DAILY_API_KEY" in pipeline.PROVIDER_KEY_VARIABLES
    assert set(required_provider_keys()) <= set(pipeline.PROVIDER_KEY_VARIABLES)


def test_the_web_and_phone_channels_run_the_same_model():
    """F13 asks for parity: the same scripted conversation, the same database
    state on web and phone. Two different models would make that a coincidence.
    """
    from agent.vapi.assistant import MODEL_NAME

    assert PipelineConfig(room="", room_token="", base_url="").llm_model == MODEL_NAME


# --------------------------------------------------------------------------
# Without the audio stack, nothing pretends (C-30)
# --------------------------------------------------------------------------


HAVE_PIPECAT = importlib.util.find_spec("pipecat") is not None


@pytest.mark.skipif(HAVE_PIPECAT, reason="the audio stack is installed here")
def test_building_without_pipecat_says_what_is_missing():
    """CI runs with `--no-group voice`, so this is the state CI is in. The
    message has to name the fix, because the symptom — every call answering 503
    — says nothing about which of the several possible reasons it was.
    """
    config = PipelineConfig(room="r", room_token="t", base_url="http://localhost")
    with pytest.raises(PipecatUnavailable) as raised:
        build_pipeline(config)
    assert "voice" in str(raised.value)


def test_a_pipeline_is_never_built_without_a_connection():
    """The pipeline is per call, from the offer the browser sent. A transport
    with no peer would be a bot talking to nobody, holding a provider bill open.

    True whether or not the audio stack is installed, which is why this one is
    not skipped: with Pipecat absent the import guard refuses first, with it
    present the connection guard does.
    """
    config = PipelineConfig(room="r", room_token="t", base_url="http://localhost")
    with pytest.raises(PipecatUnavailable):
        build_pipeline(config, connection=None)


# --------------------------------------------------------------------------
# The page, now that it has a transport in it (C-27, C-16)
# --------------------------------------------------------------------------


def test_the_microphone_is_still_reached_only_from_the_consent_handler():
    """C-27: a spoken disclosure is not consent on the web, because by the time
    it is spoken the microphone is already live.
    """
    source = PAGE.read_text(encoding="utf-8")
    # The call, not the prose: the file header explains this rule and naming it
    # there must not be mistaken for breaking it.
    calls = [m.start() for m in re.finditer(r"mediaDevices\.getUserMedia\(", source)]
    assert len(calls) == 1
    assert calls[0] > source.index('start.addEventListener("click"')


def test_the_page_loads_no_script_from_anywhere(monkeypatch):
    """A transport library would have come from a CDN. This page has none: the
    signalling is one POST to its own origin and the WebRTC is the browser's.
    """
    source = PAGE.read_text(encoding="utf-8")
    assert not re.search(r"<script[^>]+src=", source)
    assert "import(" not in source


def test_every_request_the_page_makes_is_same_origin():
    source = PAGE.read_text(encoding="utf-8")
    for call in re.findall(r"fetch\(\s*`?([^`'\",)]*)", source):
        assert call.startswith("${API}") or call.startswith("/"), call


def test_the_page_releases_the_microphone_in_exactly_one_place():
    """One place to check that a page which is not in a call is not listening."""
    source = PAGE.read_text(encoding="utf-8")
    assert source.count("track.stop()") == 1
    assert "function hangUp" in source


def test_the_page_has_somewhere_to_play_the_agents_voice():
    source = PAGE.read_text(encoding="utf-8")
    assert 'id="agent"' in source
    assert "srcObject" in source


def test_the_page_opens_no_data_channel():
    """The browser sends no application message the server would have to trust.
    Audio in, audio out, and one signed decision made server-side per request.
    """
    source = PAGE.read_text(encoding="utf-8")
    assert "createDataChannel" not in source


def test_ice_gathering_cannot_hang_the_page():
    source = PAGE.read_text(encoding="utf-8")
    assert "setTimeout(done" in source
