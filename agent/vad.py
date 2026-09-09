"""State-dependent VAD thresholds (F12, section 6.4, C-18).

VAD detects energy, not sentence completion. Somebody reading out a four-digit
code pauses between pairs, and that pause looks exactly like a finished turn.
Raising the silence threshold globally does not fix it — it trades an agent that
interrupts for an agent that feels slow, everywhere, all the time.

So the threshold moves with the state: ~700ms normally, ~1200ms while a code is
being collected. Two things are worth being clear about.

**This is the safety net, not the mechanism.** The mechanism is the server-side
digit buffer, which survives a turn boundary however badly timed it is (F5). If
this file were deleted the system would still be correct — a cut turn would just
mean the caller's next fragment appends. That is the standing move: do not try
to make an unreliable component reliable, design so its failures are harmless.

**The numbers live in `app.config`.** The browser has to be told them and `app/`
must never import `agent/`, so the values are served from `/web/config`. What
lives here is the *policy* — which conversational state gets which threshold —
because that belongs with the pipeline that applies it.

Nothing in this module talks to the network, and nothing in it decides anything
about authority.
"""

from __future__ import annotations

from dataclasses import dataclass

# Defaults, matching `Settings.vad_default_silence_ms` and
# `vad_digit_silence_ms`. Used when the pipeline is running without having
# fetched `/web/config`; `tests/contract/test_f12_web_agent.py` asserts the two
# do not drift apart.
DEFAULT_SILENCE_MS = 700
DIGIT_SILENCE_MS = 1200

# The states in which the caller is reading out a number. Named as strings
# rather than imported from `app.services.state_machine`, because importing it
# would cross the boundary this package exists on the far side of (C-19). The
# duplication is the cost of the boundary and it is a cost worth paying;
# `test_f12_web_agent.py` asserts the two lists still agree.
DIGIT_STATES: frozenset[str] = frozenset(
    {
        "CANCEL_COLLECT_REFERENCE",
        "CANCEL_CONFIRM",
    }
)


@dataclass(frozen=True)
class VadProfile:
    """What the transport should be configured with for one state."""

    state: str
    silence_ms: int
    # Barge-in stays on in every state, including digit collection. A caller who
    # starts correcting a wrong readback must be able to cut the agent off; an
    # agent that finishes its sentence first is an agent that made the caller
    # wait to say "no, that's wrong".
    allow_interruption: bool = True

    @property
    def collecting_digits(self) -> bool:
        return self.state in DIGIT_STATES


def silence_ms_for(
    state: str,
    *,
    default_ms: int = DEFAULT_SILENCE_MS,
    digit_ms: int = DIGIT_SILENCE_MS,
) -> int:
    """How long a pause has to be, in this state, before the turn is over."""
    return digit_ms if state in DIGIT_STATES else default_ms


def profile_for(
    state: str,
    *,
    default_ms: int = DEFAULT_SILENCE_MS,
    digit_ms: int = DIGIT_SILENCE_MS,
) -> VadProfile:
    return VadProfile(
        state=state,
        silence_ms=silence_ms_for(state, default_ms=default_ms, digit_ms=digit_ms),
    )


__all__ = [
    "DEFAULT_SILENCE_MS",
    "DIGIT_SILENCE_MS",
    "DIGIT_STATES",
    "VadProfile",
    "profile_for",
    "silence_ms_for",
]
