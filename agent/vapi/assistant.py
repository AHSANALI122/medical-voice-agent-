"""The Vapi assistant configuration (F13).

Vapi is the phone channel. It gets the same tools as the web channel, its own
channel secret, and two things the web channel does not need: outbound calling
switched off, and a duration cap.

**Outbound is disabled and there is no code path that enables it.** C-07 is
denial-of-wallet, and an assistant that can place calls is an assistant that can
be talked into placing them — to a premium-rate number, in a loop, overnight.
This system has no reason to ever dial anybody, so the safe configuration is not
"outbound restricted", it is "outbound absent".

**No phone number is in this repository.** Not the demo's, not anybody's. The
number is set in the Vapi dashboard and enabled only during a recording window
(§2). `gitleaks` and `tests/contract/test_f13_phone_agent.py` both look.

The duration cap is set here *and* enforced server-side in
`app.security.rate_limit.require_call_within_duration`. A cap that only lives in
somebody else's dashboard is a cap that can be clicked off.
"""

from __future__ import annotations

from typing import Any

from agent.prompts import SYSTEM_PROMPT, tool_declarations

# Matches `Settings.max_call_seconds`. The server enforces its own copy;
# `tests/contract/test_f13_phone_agent.py` asserts the two have not drifted.
MAX_DURATION_SECONDS = 600

# The model, pinned here rather than inline so there is one place to change it.
#
# It *will* go stale. Groq decommissions model ids on its own schedule, and a
# decommissioned id fails in the least helpful way available: the assistant
# accepts the config, records no call, and says nothing at all. There is no
# error to read, because the call never starts.
#
# `scripts/check_vapi_model.py` asks Groq whether this id is still served. Run
# it when the phone demo goes quiet; it is the first thing to check, not the
# last. (`llama-3.3-70b-versatile` was the original choice here and is gone.)
MODEL_PROVIDER = "groq"
MODEL_NAME = "openai/gpt-oss-120b"

# Voice and transcriber default to providers Vapi bundles, so a fresh account
# with no provider keys can place a call. This matters more than it sounds: a
# provider Vapi has no credential for does not raise anything useful, it just
# produces an assistant that never speaks — and "never speaks" is
# indistinguishable from a dozen other faults.
#
# Spec §1.2 names ElevenLabs for the phone channel, and that is still the right
# choice for a recorded walkthrough. It needs an ElevenLabs credential added to
# the Vapi account first; pass voice_provider="11labs" once it is there.
VOICE_PROVIDER = "vapi"
VOICE_ID = "Elliot"

# Spoken before anything else, on every call. C-15: the disclosure is a spoken
# fact, not a question, and on the phone there is no UI gate to put it behind.
FIRST_MESSAGE = (
    "This call is recorded, and you're speaking with an AI assistant. "
    "I can book or cancel an appointment. I can't give medical advice. "
    "Would you like to book, or cancel?"
)

END_CALL_MESSAGE = "Thanks for calling. Goodbye."


def _server_tool(name: str, declaration: dict[str, Any], webhook_url: str) -> dict[str, Any]:
    """One tool, in Vapi's shape.

    `async: False` matters. Every one of these tools is a decision the server
    makes, and the model must not continue the conversation on an assumption
    about what the answer was going to be.
    """
    return {
        "type": "function",
        "async": False,
        "function": {
            "name": name,
            "description": declaration["description"],
            "parameters": declaration["parameters"],
        },
        "server": {"url": webhook_url, "timeoutSeconds": 10},
    }


def build_assistant(
    *,
    webhook_url: str,
    max_duration_seconds: int = MAX_DURATION_SECONDS,
    voice_provider: str = VOICE_PROVIDER,
    voice_id: str = VOICE_ID,
) -> dict[str, Any]:
    """The assistant payload, ready to be pushed to Vapi.

    Contains no secret and no phone number. The webhook secret is configured out
    of band, in the Vapi dashboard, and verified by `agent.vapi.webhook`.
    """
    return {
        "name": "VoiceBook",
        "firstMessage": FIRST_MESSAGE,
        "endCallMessage": END_CALL_MESSAGE,
        # The platform half of the duration cap (F13 acceptance).
        "maxDurationSeconds": max_duration_seconds,
        # Silence is a caller thinking, not a caller gone. Both are bounded so a
        # forgotten handset cannot hold the line open and bill for it.
        "silenceTimeoutSeconds": 30,
        "backgroundSound": "off",
        # Barge-in. A caller correcting a wrong digit readback must be able to
        # cut the agent off mid-sentence (section 6.4).
        "responseDelaySeconds": 0.2,
        "numWordsToInterruptAssistant": 2,
        "model": {
            "provider": MODEL_PROVIDER,
            "model": MODEL_NAME,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}],
            "tools": [
                _server_tool(declaration["name"], declaration, webhook_url)
                for declaration in tool_declarations()
            ],
        },
        "voice": {"provider": voice_provider, "voiceId": voice_id},
        "transcriber": {"provider": "deepgram", "model": "nova-2", "language": "en"},
        # Recording is disclosed in `firstMessage` and is what the portfolio
        # walkthrough is captured from. Transcripts are redacted before they are
        # stored anywhere on this side (F11).
        "recordingEnabled": True,
        "endCallFunctionEnabled": True,
        # No `phoneNumberId`, and no outbound configuration of any kind. See the
        # module docstring: absent, not restricted.
    }


def assistant_tool_names(assistant: dict[str, Any]) -> tuple[str, ...]:
    return tuple(t["function"]["name"] for t in assistant["model"]["tools"])


__all__ = [
    "END_CALL_MESSAGE",
    "FIRST_MESSAGE",
    "MAX_DURATION_SECONDS",
    "MODEL_NAME",
    "MODEL_PROVIDER",
    "VOICE_ID",
    "VOICE_PROVIDER",
    "assistant_tool_names",
    "build_assistant",
]
