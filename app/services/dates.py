"""Relative date parsing (F7).

Every date a caller speaks is resolved here, server-side, against the clinic's
calendar — not the caller's, not the server's UTC clock, and not the model's idea
of today. "Tomorrow" means tomorrow in Karachi because that is where the
appointment is.

The rule this module follows is the project's standing one: **do not try to make
an unreliable component reliable — design so its failures are harmless.** Spoken
dates are ambiguous in ways no parser settles ("next Tuesday" genuinely means two
different days to two people), so this module does two things instead of trying
to be clever:

1. It refuses rather than guesses whenever a phrase has more than one honest
   reading, and hands back a fixed clarifying question.
2. It returns a `spoken` form for everything it does resolve, so the agent reads
   the date back — "Tuesday the tenth" — and a misparse is caught by the caller
   in the same turn rather than discovered at the clinic door.

Nothing here queries anything or decides permission. It maps text to a date.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date as Date
from datetime import datetime, timedelta, timezone
from enum import Enum

from app.config import get_settings

_PUNCTUATION = re.compile(r"[^a-z0-9/]+")

WEEKDAYS: dict[str, int] = {
    "monday": 0, "mon": 0,
    "tuesday": 1, "tue": 1, "tues": 1,
    "wednesday": 2, "wed": 2,
    "thursday": 3, "thu": 3, "thur": 3, "thurs": 3,
    "friday": 4, "fri": 4,
    "saturday": 5, "sat": 5,
    "sunday": 6, "sun": 6,
}

MONTHS: dict[str, int] = {
    "january": 1, "jan": 1,
    "february": 2, "feb": 2,
    "march": 3, "mar": 3,
    "april": 4, "apr": 4,
    "may": 5,
    "june": 6, "jun": 6,
    "july": 7, "jul": 7,
    "august": 8, "aug": 8,
    "september": 9, "sep": 9, "sept": 9,
    "october": 10, "oct": 10,
    "november": 11, "nov": 11,
    "december": 12, "dec": 12,
}

# Spoken ordinals. A caller says "the fifteenth" at least as often as "the 15th",
# and a transcriber renders it either way.
ORDINAL_WORDS: dict[str, int] = {
    "first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5,
    "sixth": 6, "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10,
    "eleventh": 11, "twelfth": 12, "thirteenth": 13, "fourteenth": 14,
    "fifteenth": 15, "sixteenth": 16, "seventeenth": 17, "eighteenth": 18,
    "nineteenth": 19, "twentieth": 20, "twentyfirst": 21, "twentysecond": 22,
    "twentythird": 23, "twentyfourth": 24, "twentyfifth": 25, "twentysixth": 26,
    "twentyseventh": 27, "twentyeighth": 28, "twentyninth": 29, "thirtieth": 30,
    "thirtyfirst": 31,
}

SMALL_NUMBERS: dict[str, int] = {
    "a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12, "thirteen": 13, "fourteen": 14,
}

# Phrases with no single honest reading. Each one gets a question, never a guess.
VAGUE_PHRASES: tuple[str, ...] = (
    "next week",
    "the week after",
    "next month",
    "sometime",
    "some time",
    "soon",
    "whenever",
    "any day",
    "any time",
    "asap",
    "as soon as possible",
    "the weekend",
    "this weekend",
    "next weekend",
    "later",
    "in the new year",
)


class DateOutcome(str, Enum):
    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    PAST = "past"
    UNPARSED = "unparsed"


# Fixed server-side clarifications, for the same reason the safety replies are
# fixed: a question the model composes is a question the model can be talked out
# of asking.
CLARIFY_AMBIGUOUS = "Which day did you have in mind? A day and a date, if you can."
CLARIFY_PAST = "That date has already passed. Which day would you like instead?"
CLARIFY_UNPARSED = "Sorry, I didn't catch the date. Which day would you like?"

_CLARIFICATIONS = {
    DateOutcome.AMBIGUOUS: CLARIFY_AMBIGUOUS,
    DateOutcome.PAST: CLARIFY_PAST,
    DateOutcome.UNPARSED: CLARIFY_UNPARSED,
}


@dataclass(frozen=True)
class DateResolution:
    outcome: DateOutcome
    value: Date | None = None
    candidates: tuple[Date, ...] = ()
    matched_by: str = "none"

    @property
    def clarification(self) -> str | None:
        return _CLARIFICATIONS.get(self.outcome)

    @property
    def spoken(self) -> str | None:
        """The readback. This is the control that makes a misparse harmless."""
        if self.value is None:
            return None
        return spoken_day(self.value)


_ORDINAL_SUFFIX = {1: "st", 2: "nd", 3: "rd"}


def _ordinal(day: int) -> str:
    if 11 <= day <= 13:
        return f"{day}th"
    return f"{day}{_ORDINAL_SUFFIX.get(day % 10, 'th')}"


def spoken_day(value: Date) -> str:
    """A date as a person says it: "Tuesday the 15th".

    One readback format for the whole system. Two would be a defect on their
    own — the slot offer and the date confirmation describe the same day to the
    same caller, and "the 9" in one place and "the 9th" in the other is how a
    caller starts wondering whether they are two different days.
    """
    return f"{value.strftime('%A')} the {_ordinal(value.day)}"


def clinic_today(now: datetime | None = None) -> Date:
    """Today in the clinic's timezone. The only definition of "today" this
    system uses, because the appointment happens where the clinic is.
    """
    now = now or datetime.now(timezone.utc)
    return now.astimezone(get_settings().clinic_tz).date()


def _normalize(raw: str) -> str:
    return _PUNCTUATION.sub(" ", raw.lower()).strip()


def _next_weekday(today: Date, weekday: int) -> Date:
    """The next occurrence strictly after today.

    "Next Tuesday" said on a Tuesday means the Tuesday coming, not this one —
    nobody books the day they are already standing in and calls it next. The
    readback is what catches the case where they meant the week after.
    """
    ahead = (weekday - today.weekday()) % 7
    return today + timedelta(days=ahead or 7)


def _day_of_month(today: Date, day: int) -> Date | None:
    """The next occurrence of a bare day number, rolling into the next month."""
    for month_offset in range(0, 3):
        month = today.month + month_offset
        year = today.year + (month - 1) // 12
        month = (month - 1) % 12 + 1
        try:
            candidate = Date(year, month, day)
        except ValueError:
            continue
        if candidate >= today:
            return candidate
    return None


def _safe_date(year: int, month: int, day: int) -> Date | None:
    try:
        return Date(year, month, day)
    except ValueError:
        return None


def parse_spoken_date(
    raw: str, *, today: Date | None = None, allow_past: bool = False
) -> DateResolution:
    """Resolve one spoken date phrase.

    `allow_past` is set by the cancellation flow, where an appointment earlier
    today is a perfectly ordinary thing to cancel. The booking flow leaves it
    false, so a past date reprompts (F7 acceptance).
    """
    today = today or clinic_today()
    text = _normalize(raw)
    if not text:
        return DateResolution(DateOutcome.UNPARSED)

    tokens = text.split()

    for phrase in VAGUE_PHRASES:
        if f" {phrase} " in f" {text} ":
            return DateResolution(DateOutcome.AMBIGUOUS, matched_by="vague")

    # Two weekdays, or two ordinals, in one breath: the caller offered options
    # rather than a date. Asking is the only honest move.
    named_weekdays = {WEEKDAYS[t] for t in tokens if t in WEEKDAYS}
    if len(named_weekdays) > 1:
        return DateResolution(
            DateOutcome.AMBIGUOUS,
            candidates=tuple(sorted(_next_weekday(today, w) for w in named_weekdays)),
            matched_by="two_weekdays",
        )

    resolved = (
        _try_iso(text)
        or _try_numeric(text, today)
        or _try_offset(text, tokens, today)
        or _try_month_and_day(tokens, today)
        or _try_weekday(text, tokens, named_weekdays, today)
        or _try_bare_ordinal(tokens, today)
    )

    if resolved is None:
        return DateResolution(DateOutcome.UNPARSED)
    if resolved.outcome is not DateOutcome.RESOLVED:
        return resolved

    assert resolved.value is not None
    if resolved.value < today and not allow_past:
        return DateResolution(
            DateOutcome.PAST, value=resolved.value, matched_by=resolved.matched_by
        )

    # A weekday and a date that disagree — "Tuesday the 15th" when the 15th is a
    # Sunday — is conflicting information, not a date. Ask.
    if named_weekdays and resolved.matched_by not in {"weekday", "offset"}:
        if resolved.value.weekday() not in named_weekdays:
            return DateResolution(DateOutcome.AMBIGUOUS, matched_by="weekday_conflict")

    return resolved


# ------------------------------------------------------------- strategies


def _try_iso(text: str) -> DateResolution | None:
    match = re.fullmatch(r"(\d{4})\s(\d{1,2})\s(\d{1,2})", text)
    if not match:
        return None
    value = _safe_date(int(match[1]), int(match[2]), int(match[3]))
    if value is None:
        return DateResolution(DateOutcome.UNPARSED)
    return DateResolution(DateOutcome.RESOLVED, value=value, matched_by="iso")


def _try_numeric(text: str, today: Date) -> DateResolution | None:
    """A slashed pair. 3/4 is the third of April to half the world and the
    fourth of March to the other half, so it is asked about, not assumed.
    """
    match = re.fullmatch(r"(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?", text.replace(" ", ""))
    if not match:
        return None

    first, second = int(match[1]), int(match[2])
    year = today.year
    if match[3]:
        year = int(match[3])
        year += 2000 if year < 100 else 0

    if first <= 12 and second <= 12 and first != second:
        candidates = tuple(
            d for d in (_safe_date(year, second, first), _safe_date(year, first, second)) if d
        )
        return DateResolution(
            DateOutcome.AMBIGUOUS, candidates=candidates, matched_by="numeric"
        )

    # Day-first when only one reading is possible.
    value = _safe_date(year, second, first) or _safe_date(year, first, second)
    if value is None:
        return DateResolution(DateOutcome.UNPARSED)
    return DateResolution(DateOutcome.RESOLVED, value=value, matched_by="numeric")


def _try_offset(text: str, tokens: list[str], today: Date) -> DateResolution | None:
    padded = f" {text} "

    if " day after tomorrow " in padded:
        return DateResolution(
            DateOutcome.RESOLVED, value=today + timedelta(days=2), matched_by="offset"
        )
    if " day before yesterday " in padded:
        return DateResolution(
            DateOutcome.RESOLVED, value=today - timedelta(days=2), matched_by="offset"
        )
    if " tomorrow " in padded or " tmrw " in padded:
        return DateResolution(
            DateOutcome.RESOLVED, value=today + timedelta(days=1), matched_by="offset"
        )
    if " yesterday " in padded:
        return DateResolution(
            DateOutcome.RESOLVED, value=today - timedelta(days=1), matched_by="offset"
        )
    if " today " in padded or " tonight " in padded:
        return DateResolution(DateOutcome.RESOLVED, value=today, matched_by="offset")

    match = re.search(r"\bin (\w+) (day|days|week|weeks)\b", text)
    if match:
        word = match[1]
        count = int(word) if word.isdigit() else SMALL_NUMBERS.get(word, 0)
        if not count:
            return DateResolution(DateOutcome.UNPARSED)
        days = count * (7 if match[2].startswith("week") else 1)
        return DateResolution(
            DateOutcome.RESOLVED, value=today + timedelta(days=days), matched_by="offset"
        )

    if re.search(r"\blast (\w+)\b", text):
        word = re.search(r"\blast (\w+)\b", text)[1]
        if word in WEEKDAYS:
            back = (today.weekday() - WEEKDAYS[word]) % 7
            value = today - timedelta(days=back or 7)
            return DateResolution(DateOutcome.RESOLVED, value=value, matched_by="offset")

    return None


def _try_month_and_day(tokens: list[str], today: Date) -> DateResolution | None:
    month = next((MONTHS[t] for t in tokens if t in MONTHS), None)
    if month is None:
        return None

    day = _find_day_number(tokens)
    if day is None:
        # A month with no day in it is a month, not a date.
        return DateResolution(DateOutcome.AMBIGUOUS, matched_by="month_only")

    year = today.year if month >= today.month else today.year + 1
    value = _safe_date(year, month, day)
    if value is None:
        return DateResolution(DateOutcome.UNPARSED)
    return DateResolution(DateOutcome.RESOLVED, value=value, matched_by="month_day")


def _try_weekday(
    text: str, tokens: list[str], named: set[int], today: Date
) -> DateResolution | None:
    if not named:
        return None
    weekday = next(iter(named))

    # "Tuesday the 15th": the ordinal is the specific claim, so it wins, and the
    # conflict check in parse_spoken_date catches a disagreement.
    day = _find_day_number(tokens)
    if day is not None:
        value = _day_of_month(today, day)
        if value is None:
            return DateResolution(DateOutcome.UNPARSED)
        return DateResolution(DateOutcome.RESOLVED, value=value, matched_by="weekday_day")

    return DateResolution(
        DateOutcome.RESOLVED, value=_next_weekday(today, weekday), matched_by="weekday"
    )


def _try_bare_ordinal(tokens: list[str], today: Date) -> DateResolution | None:
    """A day of the month with nothing else around it.

    This is the loosest strategy in the module and therefore the strictest about
    what it accepts: the number must be *marked* as a date, by an ordinal
    suffix, an ordinal word, or a preceding "the". A naked number is not a date.
    Found by feeding it "{{7*7}}", which normalizes to "7 7" and cheerfully
    resolved to the seventh.
    """
    day = _find_marked_day_number(tokens)
    if day is None:
        return None
    value = _day_of_month(today, day)
    if value is None:
        return DateResolution(DateOutcome.UNPARSED)
    return DateResolution(DateOutcome.RESOLVED, value=value, matched_by="ordinal")


def _find_day_number(tokens: list[str]) -> int | None:
    """A day of the month, spoken as a numeral or as a word.

    Used only where a month or a weekday has already supplied the context that
    makes a bare number a date — "March 15", "Tuesday the 10th".
    """
    for token in tokens:
        if token in ORDINAL_WORDS:
            return ORDINAL_WORDS[token]
        stripped = re.fullmatch(r"(\d{1,2})(st|nd|rd|th)?", token)
        if stripped:
            value = int(stripped[1])
            if 1 <= value <= 31:
                return value
    return None


def _find_marked_day_number(tokens: list[str]) -> int | None:
    """The same, but only when the number is explicitly marked as a date."""
    previous = ""
    for token in tokens:
        if token in ORDINAL_WORDS:
            return ORDINAL_WORDS[token]
        suffixed = re.fullmatch(r"(\d{1,2})(st|nd|rd|th)", token)
        if suffixed and 1 <= int(suffixed[1]) <= 31:
            return int(suffixed[1])
        if previous == "the" and re.fullmatch(r"\d{1,2}", token) and 1 <= int(token) <= 31:
            return int(token)
        previous = token
    return None
