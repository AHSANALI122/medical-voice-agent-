"""F12 — the model's tool calls actually reach the API (C-19, C-04, C-09, C-30).

The gap these close: declaring a tool tells the model it exists, and does not
make it do anything. The pipeline declared all seven and registered a handler
for none, so the model emitted `search_doctors`, Pipecat produced an empty
result on the spot, and no request ever left the process. The log said
`Calling function [search_doctors] with arguments {'specialty': 'Cardiology'}`
and the API saw nothing at all — the two halves each looked fine on their own.

Everything here runs without Pipecat: a handler is a coroutine over a tool
client, and that is testable with neither a microphone nor a model.
"""

from __future__ import annotations

import asyncio

import pytest

from agent.client import TOOLS, ToolResponse
from agent.pipecat.functions import register_tools, result_for
from agent.toolcalls import (
    ALLOWED_ARGUMENTS,
    NEEDS_IDEMPOTENCY_KEY,
    NEVER_FROM_THE_MODEL,
    sanitize,
)
from agent.turn import (
    PROVIDER_FAILURE_UTTERANCE,
    RATE_LIMITED_UTTERANCE,
    UNIFORM_REFUSAL_UTTERANCE,
)


class _RecordingClient:
    """A tool client that records rather than sends."""

    def __init__(self, response: ToolResponse | None = None) -> None:
        self.session_id = "sess-123"
        self.calls: list[tuple[str, dict]] = []
        self._response = response or ToolResponse(
            tool="x", status_code=200, body={"results": []}, latency_ms=1.0
        )

    def call(self, tool: str, **arguments):
        self.calls.append((tool, arguments))
        return self._response


class _FakeLLM:
    def __init__(self) -> None:
        self.registered: dict[str, object] = {}

    def register_function(self, name, handler, **_kwargs):
        self.registered[name] = handler


class _Params:
    def __init__(self, arguments, tool_call_id="fc-1"):
        self.arguments = arguments
        self.tool_call_id = tool_call_id
        self.results: list[dict] = []

    async def result_callback(self, result):
        self.results.append(result)


def _run(handler, params):
    asyncio.run(handler(params))
    return params.results[-1]


# --------------------------------------------------------------------------
# The bug itself
# --------------------------------------------------------------------------


def test_a_declared_tool_has_a_handler():
    """The whole failure in one assertion: the model was offered seven tools and
    could reach none of them.
    """
    llm = _FakeLLM()
    register_tools(llm, _RecordingClient())

    offered = {tool["name"] for tool in __import__(
        "agent.prompts", fromlist=["tool_declarations"]
    ).tool_declarations()}
    assert offered <= set(llm.registered)


def test_calling_a_tool_reaches_the_client(monkeypatch):
    llm = _FakeLLM()
    client = _RecordingClient()
    register_tools(llm, client)

    _run(llm.registered["search_doctors"], _Params({"specialty": "Cardiology"}))

    assert client.calls
    tool, arguments = client.calls[0]
    assert tool == "search_doctors"
    assert arguments["specialty"] == "Cardiology"


# --------------------------------------------------------------------------
# What the model may not send, and may not choose (C-04, F15)
# --------------------------------------------------------------------------


def test_the_session_is_supplied_and_never_taken_from_the_model():
    """A model that can pick a session id can pick somebody else's."""
    llm = _FakeLLM()
    client = _RecordingClient()
    register_tools(llm, client)

    _run(
        llm.registered["search_doctors"],
        _Params({"specialty": "Cardiology", "session_id": "somebody-elses"}),
    )

    _, arguments = client.calls[0]
    assert arguments["session_id"] == "sess-123"


def test_an_argument_outside_the_allowlist_is_dropped_silently():
    """Dropped, not refused. An error naming the rejected field teaches an
    injected utterance what to try next.
    """
    llm = _FakeLLM()
    client = _RecordingClient()
    register_tools(llm, client)

    _run(
        llm.registered["search_doctors"],
        _Params({"specialty": "Cardiology", "appointment_id": 7, "patient_id": 3}),
    )

    _, arguments = client.calls[0]
    assert "appointment_id" not in arguments
    assert "patient_id" not in arguments


def test_no_tool_accepts_a_database_identifier():
    """C-04. The model says "the second one" and the server resolves it against
    the list it offered.
    """
    for tool, allowed in ALLOWED_ARGUMENTS.items():
        for name in allowed:
            assert not name.endswith("_id"), f"{tool} accepts {name}"


def test_the_idempotency_key_is_minted_here_and_reused_on_a_retry():
    """F15. A key the model picks is a key an attacker picked; a fresh key per
    attempt turns one booking into two.
    """
    llm = _FakeLLM()
    client = _RecordingClient()
    register_tools(llm, client)

    first = _Params({"slot_ordinal": 1, "patient_name": "Ahmed Khan"}, "fc-same")
    second = _Params({"slot_ordinal": 1, "patient_name": "Ahmed Khan"}, "fc-same")
    _run(llm.registered["book_appointment"], first)
    _run(llm.registered["book_appointment"], second)

    keys = [arguments["idempotency_key"] for _, arguments in client.calls]
    assert keys[0] == keys[1]


def test_a_different_tool_call_gets_a_different_key():
    llm = _FakeLLM()
    client = _RecordingClient()
    register_tools(llm, client)

    _run(llm.registered["book_appointment"], _Params({"slot_ordinal": 1}, "fc-a"))
    _run(llm.registered["book_appointment"], _Params({"slot_ordinal": 1}, "fc-b"))

    keys = [arguments["idempotency_key"] for _, arguments in client.calls]
    assert keys[0] != keys[1]


def test_a_model_supplied_idempotency_key_is_ignored():
    llm = _FakeLLM()
    client = _RecordingClient()
    register_tools(llm, client)

    _run(
        llm.registered["book_appointment"],
        _Params({"slot_ordinal": 1, "idempotency_key": "chosen-by-the-model"}),
    )

    _, arguments = client.calls[0]
    assert arguments["idempotency_key"] != "chosen-by-the-model"


def test_sanitize_never_passes_the_two_the_agent_owns():
    for tool in ALLOWED_ARGUMENTS:
        cleaned = sanitize(tool, {name: "x" for name in NEVER_FROM_THE_MODEL})
        assert cleaned == {}


# --------------------------------------------------------------------------
# The screen and the session are not tools (F10)
# --------------------------------------------------------------------------


def test_the_model_cannot_call_the_screen_or_open_a_session():
    """A guardrail the model can invoke is a guardrail it can invoke and then
    ignore. `screen_turn` is a pipeline stage; `create_session` happens before a
    call exists.
    """
    llm = _FakeLLM()
    register_tools(llm, _RecordingClient())

    assert "screen_turn" not in llm.registered
    assert "create_session" not in llm.registered


def test_nothing_outside_the_published_surface_is_registered():
    llm = _FakeLLM()
    register_tools(llm, _RecordingClient())
    assert set(llm.registered) <= set(TOOLS)
    assert "list_my_appointments" not in llm.registered


# --------------------------------------------------------------------------
# What comes back (6.2, C-09, C-30)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (403, UNIFORM_REFUSAL_UTTERANCE),
        (401, UNIFORM_REFUSAL_UTTERANCE),
        (429, RATE_LIMITED_UTTERANCE),
        (0, PROVIDER_FAILURE_UTTERANCE),
        (500, PROVIDER_FAILURE_UTTERANCE),
    ],
)
def test_a_failure_hands_the_model_the_servers_words(status, expected):
    response = ToolResponse(
        tool="cancel_appointment",
        status_code=status,
        body={"detail": "something the caller must never hear"},
        latency_ms=1.0,
    )
    result = result_for(response)
    assert result == {"ok": False, "say": expected}


def test_a_failure_hands_the_model_no_detail_and_no_status():
    """A model that can see which failure it was can be argued out of it."""
    response = ToolResponse(
        tool="cancel_appointment",
        status_code=403,
        body={"detail": "no such appointment", "reason": "no_match"},
        latency_ms=1.0,
        correlation_id="corr-42",
    )
    result = result_for(response)
    assert set(result) == {"ok", "say"}
    assert "403" not in str(result)
    assert "no_match" not in str(result)
    assert "corr-42" not in str(result)


def test_a_success_masks_the_reference_before_the_model_sees_it():
    """5.1. The reference is spoken once, and the server composes that sentence
    itself in `spoken` — so the model can say it without it becoming a line in a
    transcript that outlives the moment.
    """
    response = ToolResponse(
        tool="book_appointment",
        status_code=200,
        body={
            "confirmed": True,
            "spoken": "Booked. Your reference is 4 7 2 9.",
            "reference": "4729",
        },
        latency_ms=1.0,
    )
    result = result_for(response)
    assert result["reference"] != "4729"
    assert result["spoken"] == "Booked. Your reference is 4 7 2 9."


def test_a_tool_failure_is_not_an_exception():
    """C-30. An unreachable API is an ordinary outcome with defined behaviour,
    and the call continues rather than the pipeline crashing.
    """
    llm = _FakeLLM()
    client = _RecordingClient(
        ToolResponse(tool="x", status_code=0, body={}, latency_ms=1.0)
    )
    register_tools(llm, client)

    result = _run(llm.registered["search_doctors"], _Params({"specialty": "X"}))
    assert result == {"ok": False, "say": PROVIDER_FAILURE_UTTERANCE}


# --------------------------------------------------------------------------
# Parity with the phone (F13)
# --------------------------------------------------------------------------


def test_both_channels_read_one_allowlist():
    """Two copies is the most reliable way to lose parity quietly: somebody
    widens one, the other keeps refusing, and the conversation that proves
    parity is the one nobody runs afterwards.
    """
    from agent.vapi import webhook

    assert webhook.ALLOWED_ARGUMENTS is ALLOWED_ARGUMENTS
    assert webhook.NEEDS_IDEMPOTENCY_KEY is NEEDS_IDEMPOTENCY_KEY


def test_the_allowlist_covers_every_tool_the_model_is_offered():
    from agent.prompts import tool_declarations

    offered = {tool["name"] for tool in tool_declarations()}
    assert offered == set(ALLOWED_ARGUMENTS)
