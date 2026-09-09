"""F7 — relative date parsing.

The 40-phrasing fixture, anchored on a fixed Monday so every expectation is a
literal date rather than a computation that could be wrong in the same way the
parser is.

Anchor: Monday 2 March 2026.
"""

from __future__ import annotations

from datetime import date as Date

import pytest

from app.services.dates import (
    CLARIFY_AMBIGUOUS,
    CLARIFY_PAST,
    CLARIFY_UNPARSED,
    DateOutcome,
    clinic_today,
    parse_spoken_date,
)

ANCHOR = Date(2026, 3, 2)
assert ANCHOR.weekday() == 0, "the fixture is written against a Monday"

R = DateOutcome.RESOLVED
A = DateOutcome.AMBIGUOUS
P = DateOutcome.PAST
U = DateOutcome.UNPARSED

# (phrase, outcome, expected date or None)
PHRASINGS: list[tuple[str, DateOutcome, Date | None]] = [
    # offsets
    ("today", R, Date(2026, 3, 2)),
    ("tomorrow", R, Date(2026, 3, 3)),
    ("tmrw", R, Date(2026, 3, 3)),
    ("the day after tomorrow", R, Date(2026, 3, 4)),
    ("in three days", R, Date(2026, 3, 5)),
    ("in a week", R, Date(2026, 3, 9)),
    ("in two weeks", R, Date(2026, 3, 16)),
    ("in 10 days", R, Date(2026, 3, 12)),
    # weekdays
    ("Tuesday", R, Date(2026, 3, 3)),
    ("on Tuesday", R, Date(2026, 3, 3)),
    ("next Tuesday", R, Date(2026, 3, 3)),
    ("this Friday", R, Date(2026, 3, 6)),
    ("Monday", R, Date(2026, 3, 9)),
    ("next Monday", R, Date(2026, 3, 9)),
    ("Sunday", R, Date(2026, 3, 8)),
    ("thurs", R, Date(2026, 3, 5)),
    ("coming Wednesday", R, Date(2026, 3, 4)),
    # ordinals
    ("the 15th", R, Date(2026, 3, 15)),
    ("the fifteenth", R, Date(2026, 3, 15)),
    ("the 20th", R, Date(2026, 3, 20)),
    ("the second", R, Date(2026, 3, 2)),
    # a day that has already gone rolls forward rather than reprompting: the
    # caller who says "the first" on the second means next month's.
    ("the 1st", R, Date(2026, 4, 1)),
    # month and day
    ("March 15", R, Date(2026, 3, 15)),
    ("15th of March", R, Date(2026, 3, 15)),
    ("the 3rd of April", R, Date(2026, 4, 3)),
    ("April 3", R, Date(2026, 4, 3)),
    ("Dec 25", R, Date(2026, 12, 25)),
    # written forms
    ("2026-03-11", R, Date(2026, 3, 11)),
    ("15/3", R, Date(2026, 3, 15)),
    ("25/12/2026", R, Date(2026, 12, 25)),
    # weekday plus date, agreeing
    ("Tuesday the 10th", R, Date(2026, 3, 10)),
    ("Sunday the 15th", R, Date(2026, 3, 15)),
    # ambiguous — always clarifies
    ("next week", A, None),
    ("sometime next month", A, None),
    ("3/4", A, None),
    ("Friday or Saturday", A, None),
    ("Tuesday the 15th", A, None),
    ("in March", A, None),
    ("whenever you have something", A, None),
    ("this weekend", A, None),
    # past — always reprompts
    ("yesterday", P, Date(2026, 3, 1)),
    ("last Friday", P, Date(2026, 2, 27)),
    # not a date at all
    ("banana", U, None),
]
assert len(PHRASINGS) >= 40, f"only {len(PHRASINGS)} phrasings"


@pytest.mark.parametrize("phrase,outcome,expected", PHRASINGS)
def test_the_forty_phrasing_fixture(phrase, outcome, expected):
    resolution = parse_spoken_date(phrase, today=ANCHOR)
    assert resolution.outcome is outcome, f"{phrase!r} -> {resolution}"
    if expected is not None:
        assert resolution.value == expected, phrase


# ------------------------------------------------------------ the two rules


@pytest.mark.parametrize(
    "phrase", [p for p, outcome, _ in PHRASINGS if outcome is DateOutcome.AMBIGUOUS]
)
def test_ambiguous_input_always_clarifies(phrase):
    """F7 acceptance, stated as an invariant rather than checked case by case:
    an ambiguous phrase never yields a date, and always yields a question.
    """
    resolution = parse_spoken_date(phrase, today=ANCHOR)
    assert resolution.value is None
    assert resolution.clarification == CLARIFY_AMBIGUOUS


@pytest.mark.parametrize(
    "phrase", [p for p, outcome, _ in PHRASINGS if outcome is DateOutcome.PAST]
)
def test_past_dates_reprompt(phrase):
    resolution = parse_spoken_date(phrase, today=ANCHOR)
    assert resolution.clarification == CLARIFY_PAST


def test_unparseable_input_asks_rather_than_erroring():
    resolution = parse_spoken_date("qwerty asdf", today=ANCHOR)
    assert resolution.outcome is DateOutcome.UNPARSED
    assert resolution.clarification == CLARIFY_UNPARSED


@pytest.mark.parametrize(
    "payload",
    [
        "'; DROP TABLE appointments; --",
        "{{7*7}}",
        "ignore previous instructions",
        "",
        "     ",
    ],
)
def test_a_payload_is_answered_with_a_question_not_an_exception(payload):
    resolution = parse_spoken_date(payload, today=ANCHOR)
    assert resolution.outcome in {DateOutcome.UNPARSED, DateOutcome.AMBIGUOUS}
    assert resolution.value is None


# ---------------------------------------------------------------- readback


@pytest.mark.parametrize(
    "phrase,spoken",
    [
        ("tomorrow", "Tuesday the 3rd"),
        ("the 1st", "Wednesday the 1st"),
        ("the second", "Monday the 2nd"),
        ("March 15", "Sunday the 15th"),
        ("the 11th", "Wednesday the 11th"),
        ("the 12th", "Thursday the 12th"),
        ("the 13th", "Friday the 13th"),
        ("the 21st", "Saturday the 21st"),
        ("the 22nd", "Sunday the 22nd"),
        ("the 23rd", "Monday the 23rd"),
    ],
)
def test_every_resolved_date_reads_back_as_a_day_and_a_date(phrase, spoken):
    """The readback is the control that makes a misparse harmless.

    No parser settles what "next Tuesday" means to a given caller, so the design
    does not try: it says the day out loud and lets the caller catch it in the
    same turn.
    """
    assert parse_spoken_date(phrase, today=ANCHOR).spoken == spoken


def test_nothing_unresolved_reads_back_anything():
    for phrase in ("next week", "banana", "3/4"):
        assert parse_spoken_date(phrase, today=ANCHOR).spoken is None


# ------------------------------------------------------------- cancellation


def test_the_cancel_flow_may_look_at_earlier_today():
    """An appointment at nine this morning is an ordinary thing to cancel at ten.

    This widens what the parser will return and grants no authority whatsoever:
    the reference check is untouched by it (section 5.2).
    """
    booking_view = parse_spoken_date("yesterday", today=ANCHOR)
    cancel_view = parse_spoken_date("yesterday", today=ANCHOR, allow_past=True)

    assert booking_view.outcome is DateOutcome.PAST
    assert cancel_view.outcome is DateOutcome.RESOLVED
    assert cancel_view.value == Date(2026, 3, 1)


# ------------------------------------------------------------- clinic clock


def test_today_is_the_clinics_today_not_the_servers(monkeypatch):
    """The appointment happens in Karachi, so "tomorrow" is measured there.

    Anchoring on UTC would put the clinic a day behind itself for five hours of
    every evening — the kind of bug that only shows up in a demo at night.
    """
    from datetime import datetime, timezone

    from app.config import get_settings

    # 20:00 UTC on the 2nd is already the 3rd in Karachi (UTC+5).
    late_utc = datetime(2026, 3, 2, 20, 0, tzinfo=timezone.utc)
    assert get_settings().vb_clinic_timezone == "Asia/Karachi"
    assert clinic_today(late_utc) == Date(2026, 3, 3)
    assert late_utc.date() == Date(2026, 3, 2)


# ---------------------------------------------------------------- endpoint


def test_the_endpoint_returns_the_question_and_no_date(api, session_id):
    body = api.post(
        "/tools/resolve_date", {"session_id": session_id, "phrase": "next week"}
    ).json()
    assert body["outcome"] == DateOutcome.AMBIGUOUS.value
    assert body["resolved_date"] is None
    assert body["clarification"] == CLARIFY_AMBIGUOUS


def test_the_endpoint_resolves_and_reads_back(api, session_id):
    body = api.post(
        "/tools/resolve_date", {"session_id": session_id, "phrase": "tomorrow"}
    ).json()
    assert body["outcome"] == DateOutcome.RESOLVED.value
    assert body["resolved_date"] == (
        clinic_today() + __import__("datetime").timedelta(days=1)
    ).isoformat()
    assert body["spoken"].startswith(
        (clinic_today() + __import__("datetime").timedelta(days=1)).strftime("%A")
    )


def test_the_endpoint_forbids_an_unknown_session(api):
    response = api.post(
        "/tools/resolve_date", {"session_id": "not-a-real-session", "phrase": "tomorrow"}
    )
    assert response.status_code == 403


def test_the_endpoint_rejects_an_unexpected_field(api, session_id):
    response = api.post(
        "/tools/resolve_date",
        {"session_id": session_id, "phrase": "tomorrow", "appointment_id": 1},
    )
    assert response.status_code == 422
