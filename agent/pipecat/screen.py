"""The pre-filter, as a pipeline stage (F12, F10 — C-19, C-30).

`agent/turn.py` decides *what* a turn's verdict is. This decides what the
pipeline does about it: which frames continue downstream, what gets spoken, and
whether the call ends.

The split is deliberate and it is the same split as everywhere else in this
package. `action_for` is a pure function over a `TurnPlan`, so the rule that
matters — **a screened-out turn never reaches the model** — is asserted in CI on
a machine with no audio stack, no provider key and no microphone. The class
below is an adapter: it reads a frame, calls the pure function, and pushes what
it says to push. There is no policy in it.

Two properties are the whole reason this file exists.

**The screen runs before the model, every turn.** Not when the model asks for
it, not when something looks like an emergency. `TurnScreen` sits between the
transcriber and the context aggregator, so the model is downstream of it and
physically cannot see an utterance the screen withheld. A prompt instruction
saying "check for emergencies first" would be a request to a component this
project assumes is compromised.

**The verdict is obeyed, not weighed.** `SPEAK_AND_STOP` and `SPEAK_AND_END`
swallow the transcription. The model gets no turn in which to be persuaded that
the caller did not really mean it.

And when the screen cannot run at all — the API is unreachable — the turn stops.
Proceeding unscreened would be running the booking flow with the emergency
filter switched off, which is worse than saying nothing (C-30).
"""

from __future__ import annotations

from dataclasses import dataclass

from agent.turn import Disposition, TurnPlan


@dataclass(frozen=True)
class ScreenAction:
    """What the pipeline does with one screened turn.

    Three booleans and a string, because there are only ever three questions:
    does the model see this, what do we say, and is the call over.
    """

    forward_to_model: bool
    speak: str | None = None
    end_call: bool = False

    @property
    def silences_the_model(self) -> bool:
        return not self.forward_to_model


def action_for(plan: TurnPlan) -> ScreenAction:
    """Map a verdict onto pipeline behaviour. Total, and deliberately dull."""
    if plan.disposition is Disposition.PROCEED:
        # The only branch that lets an utterance through.
        return ScreenAction(forward_to_model=True)

    if plan.disposition is Disposition.SPEAK_AND_END:
        return ScreenAction(
            forward_to_model=False, speak=plan.utterance, end_call=True
        )

    # SPEAK_AND_STOP, and anything a later version of `Disposition` adds. A new
    # disposition this function has not been taught about must not silently
    # become "let the model have it".
    return ScreenAction(forward_to_model=False, speak=plan.utterance)


def build_turn_screen(client, *, on_state=None):  # pragma: no cover - needs pipecat
    """The adapter, constructed behind a lazy import.

    `FrameProcessor` has to be a real base class at class-definition time, so the
    class is defined inside the function rather than at module level. That keeps
    this module importable — and `action_for` testable — in an environment with
    no Pipecat.

    `on_state` is called with the conversational state the server reported, so
    the transport's VAD threshold can follow it (C-18). The state comes from the
    server on every screened turn; the agent never computes it.
    """
    import asyncio

    from pipecat.frames.frames import EndFrame, Frame, TranscriptionFrame, TTSSpeakFrame
    from pipecat.processors.frame_processor import FrameDirection, FrameProcessor

    from agent.turn import screen_turn

    class TurnScreen(FrameProcessor):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self._client = client

        async def process_frame(self, frame: Frame, direction: FrameDirection):
            await super().process_frame(frame, direction)

            if not isinstance(frame, TranscriptionFrame) or not frame.text.strip():
                # Everything else passes untouched, termination frames included.
                # A processor that swallows an EndFrame hangs the pipeline.
                await self.push_frame(frame, direction)
                return

            # `screen_turn` is a blocking HTTP call. Awaiting it on the event
            # loop would stall the loop that is carrying this call's audio, so
            # it runs on a thread. The turn is not forwarded until it returns:
            # that wait is the point.
            plan = await asyncio.to_thread(screen_turn, self._client, frame.text)
            action = action_for(plan)

            if plan.state and on_state is not None:
                on_state(plan.state)

            if action.speak:
                # The server's words, verbatim. Not a summary, not a
                # paraphrase, and never generated for this turn.
                await self.push_frame(TTSSpeakFrame(action.speak), direction)

            if action.forward_to_model:
                await self.push_frame(frame, direction)

            if action.end_call:
                await self.push_frame(EndFrame(), direction)

    return TurnScreen()


__all__ = ["ScreenAction", "action_for", "build_turn_screen"]
