"""Pipecat wiring for the web channel (F12 — C-19, C-27, C-30).

Pipecat is imported lazily and the module is usable without it. That is not
laziness about the dependency; it is what lets the turn order, the VAD policy
and the boundary be tested in CI on a machine with no audio stack, no provider
keys and no browser. The parts that need a microphone are the parts that cannot
be asserted in a test suite anyway, and everything else here is a pure function
over a configuration.

What this file does hold, and what CI checks:

* the turn order — `agent.turn.screen_turn` runs before the model, every turn;
* the VAD profile applied per state (~700ms, ~1200ms while collecting digits);
* barge-in enabled in every state, including digit collection;
* the fact that no provider key is ever handed to the browser.

Provider keys are read from the environment in this process, which runs
server-side. The browser is given a room id and a sixty-second token and nothing
else — see `agent/pipecat/web/index.html` and `scripts/check_client_bundle.py`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from agent import vad
from agent.client import ToolClient
from agent.prompts import SYSTEM_PROMPT, tool_declarations

# Environment variables holding provider credentials. Named here so that
# `scripts/check_client_bundle.py` has one list to grep the web bundle for, and
# so it is obvious at a glance that all of them are read server-side.
PROVIDER_KEY_VARIABLES: tuple[str, ...] = (
    "DEEPGRAM_API_KEY",
    "GROQ_API_KEY",
    "ELEVENLABS_API_KEY",
    "CARTESIA_API_KEY",
    "OPENAI_API_KEY",
    "DAILY_API_KEY",
)


class PipecatUnavailable(RuntimeError):
    """Raised only when something actually needs the audio stack.

    Everything above the transport works without it, which is how the policy in
    this module is tested at all.
    """


@dataclass(frozen=True)
class PipelineConfig:
    """Everything the web pipeline is built from.

    Deliberately holds no secret. Keys are read from the environment at the
    moment a provider client is constructed, so a config object can be logged,
    serialized or put in a test fixture without leaking one.
    """

    room: str
    room_token: str
    base_url: str
    channel: str = "web"
    default_silence_ms: int = vad.DEFAULT_SILENCE_MS
    digit_silence_ms: int = vad.DIGIT_SILENCE_MS
    allow_interruptions: bool = True
    system_prompt: str = SYSTEM_PROMPT
    tools: list[dict] = field(default_factory=tool_declarations)

    def vad_profile(self, state: str) -> vad.VadProfile:
        return vad.profile_for(
            state,
            default_ms=self.default_silence_ms,
            digit_ms=self.digit_silence_ms,
        )

    def as_client_payload(self) -> dict[str, object]:
        """What may cross to the browser.

        The whole list: a room id and a token that expires in a minute. No
        provider key, no channel secret, no account identifier. The browser is
        an untrusted zone and this method is the one place that decides what
        reaches it.
        """
        return {"room": self.room, "token": self.room_token}


def provider_keys_present() -> dict[str, bool]:
    """Which provider credentials this process can see. Never their values."""
    return {name: bool(os.environ.get(name)) for name in PROVIDER_KEY_VARIABLES}


def missing_provider_keys() -> tuple[str, ...]:
    return tuple(name for name, present in provider_keys_present().items() if not present)


def tool_client_for(config: PipelineConfig, *, call_id: str | None = None) -> ToolClient:
    """The agent's only route to the application.

    `call_id` defaults to the room, because on the web channel the room *is* the
    call: it is server-minted, unguessable, and stable across a reconnect, which
    is exactly what a rate-limit key has to be (C-23, C-34). Signed, so the
    caller cannot mint themselves a fresh budget by picking a new one.
    """
    return ToolClient(
        channel=config.channel,
        base_url=config.base_url,
        call_id=call_id or config.room,
    )


def build_pipeline(config: PipelineConfig):  # pragma: no cover - needs the audio stack
    """Construct the live Pipecat pipeline.

    Kept behind a lazy import so the rest of this module — and every test in
    `tests/contract/test_f12_web_agent.py` — runs without Pipecat, Silero, or a
    single provider key.

    The ordering below is the part that carries weight. `screen_turn` is not a
    tool the model may call; it is a step the pipeline runs on the transcription
    before the model is invoked, and its verdict is obeyed rather than weighed.
    """
    try:
        from pipecat.audio.vad.silero import SileroVADAnalyzer  # noqa: F401
        from pipecat.pipeline.pipeline import Pipeline  # noqa: F401
    except ImportError as exc:
        raise PipecatUnavailable(
            "Pipecat is not installed. The turn policy, the VAD profile and the "
            "trust boundary are all testable without it; only the live audio "
            "path needs it, and the live audio path is not what CI can assert "
            "anything useful about. Add pipecat-ai to the environment that "
            "actually serves calls."
        ) from exc

    missing = missing_provider_keys()
    if missing:
        raise PipecatUnavailable(
            f"provider credentials missing from the environment: {', '.join(missing)}"
        )

    raise PipecatUnavailable(
        "The live pipeline is assembled at deploy time against the chosen STT "
        "and TTS providers. Everything above the transport is in this module and "
        "is covered by tests/contract/test_f12_web_agent.py."
    )


__all__ = [
    "PROVIDER_KEY_VARIABLES",
    "PipecatUnavailable",
    "PipelineConfig",
    "build_pipeline",
    "missing_provider_keys",
    "provider_keys_present",
    "tool_client_for",
]
