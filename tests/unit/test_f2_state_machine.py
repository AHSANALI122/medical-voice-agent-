"""F2 — booking state machine."""

from __future__ import annotations

import logging

import pytest

from app.services.state_machine import (
    TERMINAL_STATES,
    Disruption,
    IllegalTransition,
    State,
    can_transition,
    disruption_plan,
    transition,
)


def test_happy_book_path_walks():
    path = [
        State.GREETING,
        State.CONSENT,
        State.INTENT,
        State.DOCTOR_SELECT,
        State.SLOT_SELECT,
        State.COLLECT_NAME,
        State.BOOK_CONFIRM,
        State.BOOKED,
    ]
    for source, target in zip(path, path[1:]):
        assert transition(source, target) is target


def test_happy_cancel_path_walks():
    path = [
        State.INTENT,
        State.CANCEL_COLLECT_NAME,
        State.CANCEL_COLLECT_DATE,
        State.CANCEL_COLLECT_REFERENCE,
        State.CANCEL_CONFIRM,
        State.CANCELLED,
    ]
    for source, target in zip(path, path[1:]):
        assert transition(source, target) is target


def test_cancel_cannot_reach_confirm_without_collecting_a_reference():
    """The structural half of C-32: there is no edge that skips the ask."""
    assert not can_transition(State.CANCEL_COLLECT_DATE, State.CANCEL_CONFIRM)
    assert not can_transition(State.CANCEL_COLLECT_NAME, State.CANCEL_CONFIRM)
    assert not can_transition(State.INTENT, State.CANCEL_CONFIRM)
    assert not can_transition(State.CANCEL_COLLECT_DATE, State.CANCELLED)


def test_illegal_transition_raises_and_is_logged(caplog):
    with caplog.at_level(logging.WARNING, logger="voicebook.state"):
        with pytest.raises(IllegalTransition):
            transition(State.GREETING, State.BOOKED, session_id="s1")
    assert any("illegal_transition" in r.message for r in caplog.records)


def test_terminal_states_are_terminal():
    for state in TERMINAL_STATES:
        assert not can_transition(state, State.INTENT)
        assert not can_transition(state, State.HANDOFF)


def test_emergency_escape_is_reachable_from_every_live_state():
    """F10 leans on this: the pre-filter must be able to abandon any flow."""
    for state in State:
        if state in TERMINAL_STATES:
            continue
        assert can_transition(state, State.ESCALATED_EMERGENCY)
        assert can_transition(state, State.HANDOFF)


def test_every_live_state_defines_all_three_disruptions():
    for state in State:
        if state in TERMINAL_STATES:
            continue
        for disruption in Disruption:
            assert disruption_plan(state, disruption)


def test_reference_state_never_reveals_whether_a_record_exists():
    """C-32: no disruption in the reference state may branch on existence."""
    plans = {
        disruption_plan(State.CANCEL_COLLECT_REFERENCE, d) for d in Disruption
    }
    assert plans == {"reprompt_reference"}
