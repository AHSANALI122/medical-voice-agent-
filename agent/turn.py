"""What the agent does with one turn of caller speech (F12, F13 — C-06, C-30).

This module is the reason the voice layer can be a microphone and a speaker. It
holds the turn *order*, and the order is not the model's to choose:

    1. screen the utterance server-side;
    2. if the server says the turn is blocked, speak the server's words and stop;
    3. only then let the model reason and call tools.

Step two is the whole of it. The server returns the exact string to say, not a
hint, so an emergency redirect is not something the model composes and therefore
not something an injected utterance can argue it out of. `blocks_flow` is
obeyed, not weighed.

Two failure modes have defined behaviour rather than an exception (C-30):

**The tool API is unreachable.** The agent says one fixed sentence and ends the
turn. It never invents a confirmation, and it never claims a booking it cannot
see in the database — an agent that says "you're booked" on a timeout has
created a patient who will not be seen.

**The caller interrupts mid-sentence.** Barge-in cancels speech, not state. The
digit buffer lives on the server precisely so that a cut turn costs nothing
(F5, section 6.4), so an interruption discards the utterance in progress and
nothing else.

Nothing here is an access decision. Every one of them is behind `agent.client`,
on the far side of an HTTP hop.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from agent.client import ToolClient, ToolResponse

# The fixed utterances. Server-supplied text always wins; these are only for the
# cases where there is no server to ask.
PROVIDER_FAILURE_UTTERANCE = (
    "I'm sorry — I'm having trouble reaching the booking system just now. "
    "Nothing has been changed. Please try again in a moment, or contact the "
    "clinic directly."
)

# Said when a caller supplies something the server refused. Identical for every
# refusal, because the caller-facing failure is uniform (6.2) and the agent is
# not permitted to elaborate on it.
UNIFORM_REFUSAL_UTTERANCE = (
    "I wasn't able to match that. Please check your details and try again, "
    "or contact the clinic directly."
)

RATE_LIMITED_UTTERANCE = (
    "I can't take that request right now. Please try again later, "
    "or contact the clinic directly."
)


class Disposition(str, Enum):
    """What the pipeline should do with this turn."""

    PROCEED = "proceed"
    # Speak `utterance` and end the turn. The model does not run.
    SPEAK_AND_STOP = "speak_and_stop"
    # Speak `utterance` and end the call. Emergencies and exhausted retries.
    SPEAK_AND_END = "speak_and_end"


@dataclass(frozen=True)
class TurnPlan:
    disposition: Disposition
    utterance: str | None = None
    escalated: bool = False
    state: str | None = None

    @property
    def model_may_run(self) -> bool:
        return self.disposition is Disposition.PROCEED


def screen_turn(client: ToolClient, utterance: str) -> TurnPlan:
    """Run the pre-filter and decide whether the model gets this turn at all.

    Called unconditionally, on every turn, before the model sees the utterance.
    Not "when the agent thinks it might be an emergency" — the whole point of a
    pre-filter is that nothing gets to decide it should be skipped.
    """
    response = client.screen(utterance)

    if not response.reachable:
        # The safety layer that matters is deterministic and lives server-side,
        # so an unreachable server means the agent cannot screen at all. It
        # stops rather than proceeding unscreened: continuing would be running
        # the booking flow with the emergency filter switched off.
        return TurnPlan(Disposition.SPEAK_AND_STOP, PROVIDER_FAILURE_UTTERANCE)

    if response.status_code == 429:
        return TurnPlan(Disposition.SPEAK_AND_END, RATE_LIMITED_UTTERANCE)

    if not response.ok:
        return TurnPlan(Disposition.SPEAK_AND_STOP, UNIFORM_REFUSAL_UTTERANCE)

    body = response.body
    if body.get("escalated"):
        return TurnPlan(
            Disposition.SPEAK_AND_END,
            body.get("reply"),
            escalated=True,
            state=body.get("state"),
        )

    if body.get("blocks_flow"):
        # Medical advice, or volunteered symptoms. One warm redirect, in the
        # server's words, and the content is not acknowledged (6.3).
        return TurnPlan(
            Disposition.SPEAK_AND_STOP, body.get("reply"), state=body.get("state")
        )

    return TurnPlan(Disposition.PROCEED, state=body.get("state"))


def utterance_for(response: ToolResponse) -> str | None:
    """The fixed thing to say when a tool call did not succeed.

    `None` means the model may narrate this one itself — which is only ever true
    for a success, where there is nothing to disclose that the response body has
    not already decided to disclose.
    """
    if not response.reachable:
        return PROVIDER_FAILURE_UTTERANCE
    if response.status_code == 429:
        return RATE_LIMITED_UTTERANCE
    if response.status_code in (401, 403):
        return UNIFORM_REFUSAL_UTTERANCE
    if response.status_code == 409:
        return (
            "That time was just taken, I'm afraid. Let me find you another one."
        )
    if response.status_code == 422:
        # A shape the server would not accept. The caller hears a re-ask, never
        # the validation error, which would leak the schema.
        return "Sorry, I didn't catch that. Could you say it again?"
    if not response.ok:
        return PROVIDER_FAILURE_UTTERANCE
    return None


@dataclass(frozen=True)
class Interruption:
    """What a barge-in cancels.

    Speech, and nothing else. The digit buffer is server-side and the session
    state is server-side, so there is no client-side accumulation for an
    interruption to corrupt — which is why this dataclass has one field and not
    five. Written down because the tempting bug is to "helpfully" clear the
    buffer on interruption, and that would throw away digits the caller has
    already said.
    """

    cancel_pending_speech: bool = True
    clear_digit_buffer: bool = False
    end_session: bool = False


def on_interruption(state: str) -> Interruption:
    """Barge-in policy. Identical in every state, deliberately.

    A caller correcting a wrong digit readback is the case that matters most,
    and it is exactly the case where an agent that refused to be interrupted
    would be worst.
    """
    return Interruption()


__all__ = [
    "Disposition",
    "Interruption",
    "PROVIDER_FAILURE_UTTERANCE",
    "RATE_LIMITED_UTTERANCE",
    "TurnPlan",
    "UNIFORM_REFUSAL_UTTERANCE",
    "on_interruption",
    "screen_turn",
    "utterance_for",
]
