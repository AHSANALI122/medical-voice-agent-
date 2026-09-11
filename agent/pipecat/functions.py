"""Connecting the model's tool calls to the only door there is (F12 — C-19).

Declaring a tool tells the model it exists. It does not make it do anything. The
gap between those two is what this file closes, and until it did the symptom was
a bot that said "let me look that up" and then had nothing to look at: the model
emitted `search_doctors`, Pipecat produced an immediate empty result, and no
request ever reached the API.

Every handler here does the same four things, in the same order:

1. **Drop what the model may not send.** `agent/toolcalls.py` holds the
   allowlist, shared with the phone channel so the two cannot drift. Nothing is
   refused with a message — a message naming the rejected field teaches an
   injected utterance what to try next.
2. **Supply what the model may not choose.** The session id is this side's, and
   so is the idempotency key: a key the model picks is a key an attacker picked
   (F15).
3. **Cross the boundary over HTTP**, signed like any external caller, on a
   thread — `ToolClient.call` blocks, and the loop it would block is carrying
   the caller's audio.
4. **Speak the server's words on failure.** `agent.turn.utterance_for` decides
   what a non-success sounds like. The model is handed that sentence and the
   fact that the call failed, and it is never handed the status code, the
   validation detail or the correlation id — a model that can see a 403 is a
   model that can be talked into explaining one (6.2, C-30).

What comes back to the model is `for_transcript()`, which masks the reference.
The reference is spoken once, at booking, and the server composes that sentence
itself in the `spoken` field — so the model can say it without it ever becoming
a line in a transcript that outlives the moment (5.1).
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from agent.client import TOOLS, ToolClient, ToolResponse
from agent.toolcalls import NEEDS_IDEMPOTENCY_KEY, sanitize
from agent.turn import utterance_for

log = logging.getLogger("voicebook.agent.functions")


class _Keys:
    """One idempotency key per tool call id, minted here and remembered.

    Remembered because a retry has to reuse it — that is the whole of F15 — and
    a fresh key on every attempt turns one booking into two. Bounded by the
    call, which ends.
    """

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}

    def for_call(self, tool_call_id: str) -> str:
        if tool_call_id not in self._keys:
            self._keys[tool_call_id] = str(uuid.uuid4())
        return self._keys[tool_call_id]


def result_for(response: ToolResponse) -> dict:
    """What the model is given back. Never the status code.

    On success, the body the server composed, with the reference masked. On
    failure, the fixed sentence for that failure and nothing else — no detail,
    no field name, no correlation id. The caller-facing failure is uniform, and
    a model that can see which failure it was can be argued out of it.
    """
    spoken = utterance_for(response)
    if spoken is None:
        return response.for_transcript()
    return {"ok": False, "say": spoken}


def register_tools(llm, client: ToolClient) -> None:
    """Give every published tool a handler that reaches the API.

    The set is closed and comes from `agent.client.TOOLS`. `create_session` and
    `screen_turn` are deliberately not registered: the first is the agent's to
    call before a call exists, and the second is a pipeline stage whose verdict
    is obeyed rather than weighed. A tool the model can invoke is a tool an
    injected utterance can invoke, and a model that could call `screen_turn`
    could call it and ignore the answer.
    """
    keys = _Keys()

    for tool in TOOLS:
        if tool in ("create_session", "screen_turn"):
            continue
        llm.register_function(tool, _handler_for(tool, client, keys))


def _handler_for(tool: str, client: ToolClient, keys: _Keys):
    async def handler(params) -> None:
        arguments = sanitize(tool, dict(params.arguments or {}))

        # Supplied here, never accepted from the model.
        arguments["session_id"] = client.session_id
        if tool in NEEDS_IDEMPOTENCY_KEY:
            arguments["idempotency_key"] = keys.for_call(params.tool_call_id)

        # Off the event loop. The loop this would block is carrying the caller's
        # audio, and a tool call takes as long as the API takes.
        response = await asyncio.to_thread(client.call, tool, **arguments)

        # The tool name and the status, and nothing from the body. A tool
        # response can carry a caller's name and a booking reference, which is
        # exactly the unbounded sink C-09 is about.
        log.info("tool_call tool=%s status=%d", tool, response.status_code)

        await params.result_callback(result_for(response))

    return handler


__all__ = ["register_tools", "result_for"]
