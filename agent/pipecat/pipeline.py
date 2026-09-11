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

    # Spec §1.2. Groq serves the LLM and Whisper both, so the default needs one
    # key; Deepgram is the alternative to benchmark STT against, not a second
    # requirement. Piper, Silero and SmallWebRTC need no account at all, which
    # is why they were chosen — a free tier that lapses takes the demo with it.
    stt: str = "groq"
    stt_model: str = "whisper-large-v3-turbo"
    llm_model: str = "openai/gpt-oss-120b"
    tts_voice: str = "en_US-ryan-high"

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


def required_provider_keys(config: "PipelineConfig | None" = None) -> tuple[str, ...]:
    """The keys this pipeline actually needs, given what it is built from.

    `PROVIDER_KEY_VARIABLES` above is the list of names that must never reach a
    browser — every credential this project might ever hold. It is the wrong
    list to demand at startup, and demanding it was a real bug: the spec picked
    Silero for VAD, Piper for TTS and SmallWebRTC for transport precisely
    because none of them needs an account, and Groq serves both the LLM and
    Whisper, so **one key runs the web demo**. Requiring all six meant the demo
    refused to start unless you had signed up for five services it does not use.

    STT is the one real choice (spec §1.2 asks for both to be benchmarked), so
    it is the one thing that changes the answer.
    """
    config = config or PipelineConfig(room="", room_token="", base_url="")
    required = {"GROQ_API_KEY"}  # the LLM, always
    if config.stt == "deepgram":
        required.add("DEEPGRAM_API_KEY")
    return tuple(sorted(required))


def missing_provider_keys(config: "PipelineConfig | None" = None) -> tuple[str, ...]:
    present = provider_keys_present()
    return tuple(
        name for name in required_provider_keys(config) if not present.get(name)
    )


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


PIPELINE_ORDER: tuple[str, ...] = (
    "transport.input",
    "stt",
    "screen",
    "context.user",
    "llm",
    "tts",
    "transport.output",
    "context.assistant",
)


def build_pipeline(config: PipelineConfig, *, connection=None, client=None):
    """Construct the live Pipecat pipeline.

    Everything above the transport — the turn policy, the VAD profile, the trust
    boundary, the screen's behaviour — is a pure function tested in CI on a
    machine with no audio stack. This function is the wiring, and wiring is the
    part a test suite cannot say anything useful about.

    The ordering is the part that carries weight, and it is written out in
    `PIPELINE_ORDER` so a test can assert it without constructing a pipeline.
    `screen` sits between the transcriber and the context aggregator. That
    position is the mechanism: the model is downstream of it and cannot see an
    utterance it withheld. Moving it one place later would turn an enforced
    filter into a suggestion — which is the same thing as not having one, given
    that this project assumes the model is compromised.
    """
    try:
        from pipecat.adapters.schemas.function_schema import FunctionSchema
        from pipecat.adapters.schemas.tools_schema import ToolsSchema
        from pipecat.audio.vad.silero import SileroVADAnalyzer
        from pipecat.audio.vad.vad_analyzer import VADParams
        from pipecat.pipeline.pipeline import Pipeline
        from pipecat.processors.aggregators.llm_context import LLMContext
        from pipecat.processors.aggregators.llm_response_universal import (
            LLMContextAggregatorPair,
            LLMUserAggregatorParams,
        )
        from pipecat.services.groq.llm import GroqLLMService
        from pipecat.services.piper.tts import PiperTTSService
        from pipecat.transports.smallwebrtc.transport import (
            SmallWebRTCTransport,
            TransportParams,
        )
    except ImportError as exc:
        raise PipecatUnavailable(
            "Pipecat is not installed. The turn policy, the VAD profile and the "
            "trust boundary are all testable without it; only the live audio "
            "path needs it, and the live audio path is not what CI can assert "
            "anything useful about. Install the voice group: "
            "`uv sync --group voice`."
        ) from exc

    missing = missing_provider_keys(config)
    if missing:
        raise PipecatUnavailable(
            f"provider credentials missing from the environment: {', '.join(missing)}"
        )

    if connection is None:
        raise PipecatUnavailable(
            "a SmallWebRTC connection is required; the pipeline is built per "
            "call, from the offer the browser sent."
        )

    if not config.allow_interruptions:
        # Pipecat 1.9 has no switch for this: a caller can always cut the agent
        # off. That is the behaviour this project wants in every state (C-18), so
        # the default is right — but a config that asked for the opposite would
        # be silently ignored, and a security setting that is silently ignored is
        # worse than one that is absent.
        raise PipecatUnavailable(
            "allow_interruptions=False is not something this runtime can honour; "
            "barge-in is always on."
        )

    from agent.pipecat.screen import build_turn_screen

    # The VAD starts on the default profile and is moved by the screen as the
    # server reports state (C-18). The agent never decides which state it is in.
    profile = config.vad_profile("INTENT")
    vad = SileroVADAnalyzer(params=VADParams(stop_secs=profile.silence_ms / 1000))

    transport = SmallWebRTCTransport(
        webrtc_connection=connection,
        params=TransportParams(audio_in_enabled=True, audio_out_enabled=True),
    )

    if config.stt == "deepgram":
        from pipecat.services.deepgram.stt import DeepgramSTTService

        stt = DeepgramSTTService(api_key=os.environ["DEEPGRAM_API_KEY"])
    else:
        from pipecat.services.groq.stt import GroqSTTService

        stt = GroqSTTService(
            api_key=os.environ["GROQ_API_KEY"],
            settings=GroqSTTService.Settings(model=config.stt_model),
        )

    llm = GroqLLMService(
        api_key=os.environ["GROQ_API_KEY"],
        settings=GroqLLMService.Settings(model=config.llm_model),
    )

    # Local. Chosen because it has no free tier that can lapse, which for an
    # always-on portfolio demo matters more than the voice quality does.
    tts = PiperTTSService(settings=PiperTTSService.Settings(voice=config.tts_voice))

    # Passed in by `start_call`, which opens the session before a peer
    # connection exists, so a call that cannot get one never starts. Built
    # here only for the tests that construct a pipeline directly.
    client = client or tool_client_for(config)

    def on_state(state: str) -> None:
        """Follow the server's state with the silence threshold.

        Somebody reading out a four-digit code pauses between pairs, and that
        pause looks exactly like a finished turn. This is the safety net; the
        mechanism is the server-side digit buffer, which survives a cut turn
        however badly timed.
        """
        vad.set_params(VADParams(stop_secs=config.vad_profile(state).silence_ms / 1000))

    screen = build_turn_screen(client, on_state=on_state)

    # The published tool surface, in the shape this runtime wants. Converted
    # rather than re-declared: `agent/prompts.py` stays the single place a tool
    # is described, so the model on the phone and the model in the browser are
    # offered the same seven things (F13 parity).
    tools = ToolsSchema(
        standard_tools=[
            FunctionSchema(
                name=tool["name"],
                description=tool["description"],
                properties=tool["parameters"].get("properties", {}),
                required=tool["parameters"].get("required", []),
            )
            for tool in config.tools
        ]
    )

    context = LLMContext(
        messages=[{"role": "system", "content": config.system_prompt}],
        tools=tools,
    )

    # The VAD lives here in 1.9, not on the transport: it is what decides a user
    # turn is over, and the aggregator is what assembles one.
    aggregators = LLMContextAggregatorPair(
        context, user_params=LLMUserAggregatorParams(vad_analyzer=vad)
    )

    pipeline = Pipeline(
        [
            transport.input(),
            stt,
            screen,
            aggregators.user(),
            llm,
            tts,
            transport.output(),
            aggregators.assistant(),
        ]
    )
    return pipeline, transport, context


# A public STUN server, needed only to discover the server's own address when it
# is behind NAT. It carries no media, no audio and no credential — the SDP it
# helps produce is exchanged over this process's own HTTPS, never through it.
ICE_SERVERS: tuple[str, ...] = ("stun:stun.l.google.com:19302",)


async def start_call(
    config: PipelineConfig,
    *,
    sdp: str,
    sdp_type: str,
    consent_given: bool,
    on_closed=None,
):  # pragma: no cover - needs the audio stack
    """Answer one browser's offer and put a bot on the other end of it.

    Returns the SDP answer and the connection, because the caller owns the
    question of how many of these may exist at once — that is a budget, and a
    budget does not belong in the function that builds pipelines.

    `on_closed` is called when the peer connection ends, so the caller can free
    whatever it reserved. Synchronous by design: it runs inside an event handler
    and anything awaited there delays the close.

    Raises `PipecatUnavailable` when the audio stack or a provider key is
    missing, which the caller turns into a 503. That is the same shape as every
    other provider failure here: an ordinary outcome with defined behaviour, not
    a crash and not a half-open call (C-30).
    """
    try:
        from pipecat.transports.smallwebrtc.connection import SmallWebRTCConnection
    except ImportError as exc:
        raise PipecatUnavailable(
            "Pipecat is not installed. Install the voice group: "
            "`uv sync --group voice`."
        ) from exc

    missing = missing_provider_keys(config)
    if missing:
        # Checked before a peer connection is created, so a misconfigured server
        # does not leave half-open connections behind every refused call.
        raise PipecatUnavailable(
            f"provider credentials missing from the environment: {', '.join(missing)}"
        )

    import asyncio

    # The session is opened here, before a peer connection exists, and that
    # placement is the fix for a real failure rather than tidiness. Every tool
    # call carries a session id, `screen_turn` included — so a pipeline that
    # started without one screened every turn with `session_id=None`, collected
    # a 422, and said "I wasn't able to match that" to whatever the caller
    # said, forever. Opening it first means a call that cannot get a session
    # never becomes a call at all.
    #
    # Consent is passed through, not assumed (C-27). The browser is the only
    # place that can know, because it is the only place where a microphone was
    # asked for.
    client = tool_client_for(config)
    opened = await asyncio.to_thread(client.open_session, consent_given=consent_given)
    if not opened.ok:
        raise PipecatUnavailable(
            f"the booking system would not open a session (status {opened.status_code})"
        )

    connection = SmallWebRTCConnection(list(ICE_SERVERS))
    await connection.initialize(sdp=sdp, type=sdp_type)

    @connection.event_handler("closed")
    async def _on_closed(closed):  # noqa: ANN001
        if on_closed is not None:
            on_closed(closed)

    # The call runs for as long as the caller stays; the offer must be answered
    # now. Detached deliberately — awaiting it here would hold the HTTP request
    # open for the length of the conversation.
    asyncio.create_task(run_call(config, connection, client))

    return connection.get_answer(), connection


async def run_call(config: PipelineConfig, connection, client=None):  # pragma: no cover
    """Serve one call, from a connected browser to a hung-up one.

    Not covered by tests, and it should not pretend to be: everything here is a
    call into Pipecat's runtime. What *is* covered is everything that decides
    anything — `action_for`, `screen_turn`, `vad.profile_for`, `PIPELINE_ORDER`,
    the tool client's boundary. This function only starts them.
    """
    import asyncio

    from pipecat.frames.frames import EndFrame
    from pipecat.pipeline.worker import PipelineWorker
    from pipecat.workers.runner import WorkerRunner

    # Off the event loop. `build_pipeline` loads the Silero model and a 120MB
    # Piper voice, and it was doing that on the loop that carries every other
    # call's audio and ICE — measured at ~10 seconds. The symptom was not a slow
    # call, it was `PipelineWorker: timeout setting the pipeline up`, which reads
    # like a Pipecat problem and is not.
    pipeline, transport, _context = await asyncio.to_thread(
        build_pipeline, config, connection=connection, client=client
    )

    worker = PipelineWorker(
        pipeline,
        # RTVI is Pipecat's client-messaging protocol and it runs over a WebRTC
        # data channel. The page opens none, deliberately — it sends no
        # application message the server would have to trust — so there is
        # nothing for RTVI to talk to and no reason to start it.
        enable_rtvi=False,
    )

    @transport.event_handler("on_client_disconnected")
    async def _on_disconnected(_transport, _client):  # noqa: ANN001
        await worker.queue_frame(EndFrame())

    await WorkerRunner().run(worker)


__all__ = [
    "PIPELINE_ORDER",
    "PROVIDER_KEY_VARIABLES",
    "PipecatUnavailable",
    "PipelineConfig",
    "build_pipeline",
    "missing_provider_keys",
    "provider_keys_present",
    "ICE_SERVERS",
    "run_call",
    "start_call",
    "required_provider_keys",
    "tool_client_for",
]
