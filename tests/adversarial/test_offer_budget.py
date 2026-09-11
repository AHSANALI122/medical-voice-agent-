"""C-07, C-23, C-34 — what one stranger may cost the signalling process.

`/api/offer` is unauthenticated because the browser holds no channel secret and
must not be given one. Before the budget existed, two things followed from that,
and both were measured against a running server rather than argued:

* thirty anonymous posts produced thirty **signed** requests into the trusted
  zone and not one 429 — an unauthenticated caller driving authenticated traffic;
* a room token is not single-use, so one minted token was worth an unbounded
  number of live pipelines inside its sixty seconds. Each one is a Silero load,
  a 120MB voice and Groq inference per turn. That is C-07 with the wallet held
  open by a sixty-second string.

The tests below are about the budget's own behaviour. The ordering property —
that the budget is checked *before* the token, so a 429 is not an oracle — is in
`tests/contract/test_f12_web_signalling.py`, where the signalling app is.
"""

from __future__ import annotations

import pytest

from agent.pipecat.budget import (
    ADMITTED,
    REFUSED_CONCURRENT,
    REFUSED_PER_IP,
    OfferBudget,
)


@pytest.fixture
def budget():
    return OfferBudget(
        max_offers_per_ip=3, window_seconds=60, max_concurrent_calls=2
    )


# --------------------------------------------------------------------------
# Per address
# --------------------------------------------------------------------------


def test_a_flood_from_one_address_stops(budget):
    verdicts = [
        budget.admit(client_ip="10.0.0.1", room=f"r{i}", now=1000.0) for i in range(5)
    ]
    assert [bool(v) for v in verdicts] == [True, True, True, False, False]
    assert verdicts[-1].reason == REFUSED_PER_IP


def test_one_address_does_not_spend_another_ones_budget(budget):
    """C-34. Budgets key on the address, and two addresses are two budgets."""
    for i in range(3):
        assert budget.admit(client_ip="10.0.0.1", room=f"r{i}", now=1000.0)
    assert budget.admit(client_ip="10.0.0.2", room="other", now=1000.0)


def test_a_refused_offer_is_still_charged(budget):
    """The attempt is what costs this process a signed request into the trusted
    zone. A budget that counted only the successes is a budget an attacker never
    touches — they send forged tokens.
    """
    for i in range(3):
        budget.admit(client_ip="10.0.0.1", room=f"r{i}", now=1000.0)
    assert not budget.admit(client_ip="10.0.0.1", room="fresh", now=1000.0)


def test_the_window_eventually_forgives(budget):
    for i in range(3):
        budget.admit(client_ip="10.0.0.1", room=f"r{i}", now=1000.0)
    assert not budget.admit(client_ip="10.0.0.1", room="x", now=1030.0)
    assert budget.admit(client_ip="10.0.0.1", room="x", now=1061.0)


def test_memory_is_bounded_by_the_window_not_by_the_attacker(budget):
    """An entry older than the window can never refuse anything, so keeping it
    would only let a long flood grow this process's memory without limit.
    """
    for minute in range(200):
        budget.admit(client_ip="10.0.0.1", room="r", now=1000.0 + minute * 61)
    assert len(budget._offers["10.0.0.1"]) <= budget.max_offers_per_ip


# --------------------------------------------------------------------------
# Concurrent calls — the expensive limit
# --------------------------------------------------------------------------


def test_the_number_of_live_calls_is_capped(budget):
    for room in ("a", "b"):
        assert budget.admit(client_ip=f"ip-{room}", room=room, now=1000.0)
        budget.register(room, object())

    verdict = budget.admit(client_ip="ip-c", room="c", now=1000.0)
    assert not verdict
    assert verdict.reason == REFUSED_CONCURRENT


def test_a_finished_call_frees_its_slot(budget):
    for room in ("a", "b"):
        budget.admit(client_ip=f"ip-{room}", room=room, now=1000.0)
        budget.register(room, object())

    budget.release("a")
    assert budget.admit(client_ip="ip-c", room="c", now=1000.0)


def test_the_cap_counts_calls_and_not_addresses(budget):
    """Two live calls is two live models, wherever they came from."""
    budget.register("a", object())
    budget.register("b", object())
    assert budget.admit(client_ip="a-new-address", room="c", now=1000.0).reason == (
        REFUSED_CONCURRENT
    )


# --------------------------------------------------------------------------
# One live call per room, and a reconnect is not an attack (C-23)
# --------------------------------------------------------------------------


def test_a_reconnect_to_a_live_room_is_admitted_even_at_the_cap(budget):
    """The room is already occupied by this caller, so admitting them again
    costs no new slot. Refusing here would break the case the design expects:
    a browser whose network blinked.
    """
    budget.register("a", object())
    budget.register("b", object())
    assert budget.live_calls == 2

    assert budget.admit(client_ip="ip-a", room="a", now=1000.0)


def test_a_reconnect_replaces_the_call_it_found(budget):
    first, second = object(), object()
    assert budget.register("a", first) is None
    assert budget.register("a", second) is first
    assert budget.live_calls == 1


def test_one_token_cannot_hold_many_calls_open(budget):
    """A room token is not single-use, so the same one can be presented all
    minute. Each presentation replaces the last rather than adding to it.
    """
    for _ in range(5):
        budget.admit(client_ip="10.0.0.1", room="same-room", now=1000.0)
        budget.register("same-room", object())
    assert budget.live_calls == 1


def test_a_replaced_calls_late_close_does_not_free_the_new_one(budget):
    """The race that would otherwise undo all of this: the old connection's
    "closed" handler fires *after* its replacement registered, and a blind pop
    frees a room whose new call is still running.
    """
    first, second = object(), object()
    budget.register("a", first)
    budget.register("a", second)

    budget.release("a", first)
    assert budget.live_calls == 1

    budget.release("a", second)
    assert budget.live_calls == 0


def test_releasing_a_room_that_was_never_live_is_harmless(budget):
    budget.release("never")
    assert budget.live_calls == 0


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_the_defaults_are_a_demo_and_not_a_service():
    fresh = OfferBudget()
    assert fresh.max_concurrent_calls <= 5
    assert fresh.max_offers_per_ip >= 3, "a reconnecting browser must not be locked out"


def test_a_nonsense_limit_falls_back_rather_than_disabling_the_budget(monkeypatch):
    """`VB_MAX_CONCURRENT_CALLS=0` must not mean "no calls" *or* "no limit" by
    accident. A misconfigured budget that silently switches itself off is the
    failure this whole file exists to prevent.
    """
    monkeypatch.setenv("VB_MAX_CONCURRENT_CALLS", "0")
    monkeypatch.setenv("VB_MAX_OFFERS_PER_IP", "not-a-number")
    fresh = OfferBudget()
    assert fresh.max_concurrent_calls > 0
    assert fresh.max_offers_per_ip > 0


def test_admission_reports_why_it_said_yes(budget):
    assert budget.admit(client_ip="1.1.1.1", room="r", now=1000.0).reason == ADMITTED
