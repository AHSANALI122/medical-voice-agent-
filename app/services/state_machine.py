"""Booking state machine (F2).

The machine holds conversational position and nothing else. It grants no
authority: reaching CANCEL_CONFIRM does not mean the caller may cancel, it means
the server has a reference to check. The check itself lives in
app.security.reference and runs on every attempt (C-38).

Illegal transitions raise. A voice agent that can be talked into skipping
COLLECT_REFERENCE is exactly the failure this file exists to make impossible.
"""

from __future__ import annotations

import logging
from enum import Enum

log = logging.getLogger("voicebook.state")


class State(str, Enum):
    GREETING = "GREETING"
    CONSENT = "CONSENT"
    INTENT = "INTENT"

    # Book path
    DOCTOR_SELECT = "DOCTOR_SELECT"
    SLOT_SELECT = "SLOT_SELECT"
    COLLECT_NAME = "COLLECT_NAME"
    BOOK_CONFIRM = "BOOK_CONFIRM"
    BOOKED = "BOOKED"

    # Cancel path
    CANCEL_COLLECT_NAME = "CANCEL_COLLECT_NAME"
    CANCEL_COLLECT_DATE = "CANCEL_COLLECT_DATE"
    CANCEL_COLLECT_REFERENCE = "CANCEL_COLLECT_REFERENCE"
    CANCEL_CONFIRM = "CANCEL_CONFIRM"
    CANCELLED = "CANCELLED"

    # Terminal
    ABANDONED = "ABANDONED"
    ESCALATED_EMERGENCY = "ESCALATED_EMERGENCY"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    HANDOFF = "HANDOFF"


TERMINAL_STATES = frozenset(
    {
        State.BOOKED,
        State.CANCELLED,
        State.ABANDONED,
        State.ESCALATED_EMERGENCY,
        State.PROVIDER_FAILURE,
        State.HANDOFF,
    }
)

# Any state may fall out of the flow into a terminal escape. The emergency
# pre-filter (F10) runs before this machine every turn and can force
# ESCALATED_EMERGENCY from anywhere.
_UNIVERSAL_EXITS = frozenset(
    {
        State.ABANDONED,
        State.ESCALATED_EMERGENCY,
        State.PROVIDER_FAILURE,
        State.HANDOFF,
    }
)

_ALLOWED: dict[State, frozenset[State]] = {
    State.GREETING: frozenset({State.CONSENT}),
    State.CONSENT: frozenset({State.INTENT}),
    State.INTENT: frozenset({State.DOCTOR_SELECT, State.CANCEL_COLLECT_NAME}),
    State.DOCTOR_SELECT: frozenset({State.SLOT_SELECT, State.DOCTOR_SELECT}),
    State.SLOT_SELECT: frozenset({State.COLLECT_NAME, State.SLOT_SELECT, State.DOCTOR_SELECT}),
    State.COLLECT_NAME: frozenset({State.BOOK_CONFIRM, State.COLLECT_NAME}),
    State.BOOK_CONFIRM: frozenset({State.BOOKED, State.SLOT_SELECT, State.COLLECT_NAME}),
    State.CANCEL_COLLECT_NAME: frozenset(
        {State.CANCEL_COLLECT_DATE, State.CANCEL_COLLECT_NAME}
    ),
    State.CANCEL_COLLECT_DATE: frozenset(
        {State.CANCEL_COLLECT_REFERENCE, State.CANCEL_COLLECT_DATE}
    ),
    # Note what is absent: there is no edge from COLLECT_DATE to CANCEL_CONFIRM.
    # The reference is always collected, including when no record matches, so
    # the flow itself is not an existence oracle (C-32).
    State.CANCEL_COLLECT_REFERENCE: frozenset(
        {State.CANCEL_CONFIRM, State.CANCEL_COLLECT_REFERENCE}
    ),
    State.CANCEL_CONFIRM: frozenset({State.CANCELLED, State.CANCEL_COLLECT_REFERENCE}),
    State.BOOKED: frozenset(),
    State.CANCELLED: frozenset(),
    State.ABANDONED: frozenset(),
    State.ESCALATED_EMERGENCY: frozenset(),
    State.PROVIDER_FAILURE: frozenset(),
    State.HANDOFF: frozenset(),
}


class IllegalTransition(Exception):
    def __init__(self, source: State, target: State) -> None:
        super().__init__(f"illegal transition {source.value} -> {target.value}")
        self.source = source
        self.target = target


def can_transition(source: State, target: State) -> bool:
    if source in TERMINAL_STATES:
        return False
    if target in _UNIVERSAL_EXITS:
        return True
    return target in _ALLOWED.get(source, frozenset())


def transition(source: State, target: State, *, session_id: str | None = None) -> State:
    if not can_transition(source, target):
        log.warning(
            "illegal_transition source=%s target=%s session=%s",
            source.value,
            target.value,
            session_id or "-",
        )
        raise IllegalTransition(source, target)
    return target


class Disruption(str, Enum):
    """The three things callers reliably do that the happy path does not cover."""

    SILENCE = "silence"
    AMBIGUITY = "ambiguity"
    OFF_TOPIC = "off_topic"


# Every non-terminal state defines a response to every disruption (F2
# acceptance). A missing entry is a build failure, not a runtime shrug: see
# tests/unit/test_state_machine.py.
_DISRUPTION_PLAN: dict[State, dict[Disruption, str]] = {
    State.GREETING: {
        Disruption.SILENCE: "repeat_disclosure",
        Disruption.AMBIGUITY: "repeat_disclosure",
        Disruption.OFF_TOPIC: "repeat_disclosure",
    },
    State.CONSENT: {
        Disruption.SILENCE: "repeat_disclosure",
        Disruption.AMBIGUITY: "repeat_disclosure",
        Disruption.OFF_TOPIC: "repeat_disclosure",
    },
    State.INTENT: {
        Disruption.SILENCE: "reprompt_intent",
        Disruption.AMBIGUITY: "reprompt_intent",
        Disruption.OFF_TOPIC: "redirect_to_intent",
    },
    State.DOCTOR_SELECT: {
        Disruption.SILENCE: "reprompt_doctor",
        Disruption.AMBIGUITY: "ask_which_doctor",
        Disruption.OFF_TOPIC: "redirect_to_doctor",
    },
    State.SLOT_SELECT: {
        Disruption.SILENCE: "reoffer_slots",
        Disruption.AMBIGUITY: "reoffer_slots",
        Disruption.OFF_TOPIC: "redirect_to_slot",
    },
    State.COLLECT_NAME: {
        Disruption.SILENCE: "reprompt_name",
        Disruption.AMBIGUITY: "reprompt_name",
        Disruption.OFF_TOPIC: "redirect_to_name",
    },
    State.BOOK_CONFIRM: {
        Disruption.SILENCE: "repeat_confirmation",
        Disruption.AMBIGUITY: "repeat_confirmation",
        Disruption.OFF_TOPIC: "repeat_confirmation",
    },
    State.CANCEL_COLLECT_NAME: {
        Disruption.SILENCE: "reprompt_name",
        Disruption.AMBIGUITY: "reprompt_name",
        Disruption.OFF_TOPIC: "redirect_to_name",
    },
    State.CANCEL_COLLECT_DATE: {
        Disruption.SILENCE: "reprompt_date",
        Disruption.AMBIGUITY: "clarify_date",
        Disruption.OFF_TOPIC: "redirect_to_date",
    },
    State.CANCEL_COLLECT_REFERENCE: {
        # Never "I could not find that booking" — the reference is asked for
        # whether or not a record exists (C-32).
        Disruption.SILENCE: "reprompt_reference",
        Disruption.AMBIGUITY: "reprompt_reference",
        Disruption.OFF_TOPIC: "reprompt_reference",
    },
    State.CANCEL_CONFIRM: {
        Disruption.SILENCE: "repeat_confirmation",
        Disruption.AMBIGUITY: "repeat_confirmation",
        Disruption.OFF_TOPIC: "repeat_confirmation",
    },
}


def disruption_plan(state: State, disruption: Disruption) -> str:
    if state in TERMINAL_STATES:
        return "end_call"
    return _DISRUPTION_PLAN[state][disruption]


def entry_state() -> State:
    return State.GREETING

