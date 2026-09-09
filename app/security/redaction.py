"""Redact before store (F11 — C-09, C-25).

Two jobs, both about text that is on its way somewhere it will outlive the call.

**Redaction (C-09).** A transcript is an unbounded PHI sink. Anything written to
a log, an event row, or an eval report passes through `redact` first, which
strikes names, dates of birth, booking references, and any run of four or more
digits. The reference matters most: it is the entire authority to cancel an
appointment (section 5.2), so a reference that survives into a stored transcript
has outlived the moment it was disclosed in and is now a credential lying in a
log file.

**Delimiting (C-25).** Transcript text handed to eval tooling — or to any other
model — is data, not instruction. `wrap_untrusted` puts it inside a marked block
and strips any occurrence of the marker from the content first, so a caller who
says the closing delimiter aloud cannot end the block early and have the rest of
their utterance read as directions.

What this module is not: it is not the control that keeps symptom text out of
the database. That control is that no symptom text is ever written in the first
place — there is no reason-for-visit field, `screen_turn` discards the utterance,
and no audit row carries one. Redaction cannot recognise a symptom, and a design
that leaned on it to try would be leaning on the wrong thing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

REDACTED_DIGITS = "[redacted-digits]"
REDACTED_DATE = "[redacted-date]"
REDACTED_NAME = "[redacted-name]"

UNTRUSTED_OPEN = "<<<UNTRUSTED_TRANSCRIPT>>>"
UNTRUSTED_CLOSE = "<<<END_UNTRUSTED_TRANSCRIPT>>>"
_DELIMITER_STRIPPED = "[delimiter-stripped]"

_MONTHS = (
    "january|february|march|april|may|june|july|august|september|october|"
    "november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec"
)

# Dates first, so a date of birth is struck whole rather than being half-eaten
# by the digit-run rule and leaving "-03-12" behind.
_DATE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    re.compile(r"\b\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}\b"),
    re.compile(rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTHS})\.?\s+\d{{2,4}}\b", re.I),
    re.compile(rf"\b(?:{_MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{2,4}}\b", re.I),
)

# "4-7-2-9" is this system's own digit-by-digit readback format (section 6.4),
# so it is the shape a reference is most likely to appear in. A plain \d{4,}
# rule walks straight past it.
_SEPARATED_DIGITS = re.compile(r"\b\d(?:[\s.\-]{1,3}\d){3,}\b")

_DIGIT_RUN = re.compile(r"\d{4,}")

# Spoken digits are how a reference actually reaches a transcript. STT writes
# "four seven two nine" far more often than it writes "4729".
_DIGIT_WORDS = (
    "zero|oh|nought|one|two|three|four|five|six|seven|eight|nine|double|triple"
)
_SPOKEN_DIGITS = re.compile(
    rf"\b(?:{_DIGIT_WORDS})(?:[\s,.\-]+(?:{_DIGIT_WORDS})){{3,}}\b", re.I
)

# The partial layer. Where no name vocabulary is supplied — an ad-hoc log line,
# a transcript captured before the caller gave their name — this catches the
# introduction phrasings people actually use. It is a net, not the control: the
# control is passing `names`.
_INTRODUCED_NAME = re.compile(
    r"\b(?P<lead>my name is|name's|this is for|this is|i'm|i am|it's for|for)\s+"
    r"(?P<name>[A-Z][a-z'\-]+(?:\s+[A-Z][a-z'\-]+){0,2})"
)


def _name_variants(names: Iterable[str]) -> list[str]:
    """Every form of a supplied name worth striking, longest first.

    Longest first so "Ahmed Khan" is replaced as one token rather than leaving
    "[redacted-name] [redacted-name]", which would still disclose that the name
    had two parts.
    """
    variants: set[str] = set()
    for raw in names:
        cleaned = (raw or "").strip()
        if not cleaned:
            continue
        variants.add(cleaned)
        for part in re.split(r"[\s\-']+", cleaned):
            # Two-letter fragments match far too much ordinary English to be
            # worth striking; three is where a name part starts being a name.
            if len(part) >= 3:
                variants.add(part)
    return sorted(variants, key=len, reverse=True)


def redact(text: str, *, names: Iterable[str] = ()) -> str:
    """Strike names, dates, references, and digit runs from one string.

    Order is deliberate and the tests pin it: dates, then separated digit runs,
    then spoken digit runs, then plain digit runs, then names. Reversing the
    first two would let the digit rule eat the year out of a date of birth and
    leave the day and month sitting in the log.
    """
    if not text:
        return text

    out = text
    for pattern in _DATE_PATTERNS:
        out = pattern.sub(REDACTED_DATE, out)
    out = _SEPARATED_DIGITS.sub(REDACTED_DIGITS, out)
    out = _SPOKEN_DIGITS.sub(REDACTED_DIGITS, out)
    out = _DIGIT_RUN.sub(REDACTED_DIGITS, out)

    for variant in _name_variants(names):
        out = re.sub(rf"\b{re.escape(variant)}\b", REDACTED_NAME, out, flags=re.I)

    out = _INTRODUCED_NAME.sub(rf"\g<lead> {REDACTED_NAME}", out)
    return out


def redact_payload(payload: Any, *, names: Iterable[str] = ()) -> Any:
    """Recursively redact every string in a structure.

    Keys are redacted too. A payload that has ended up with a caller's name as a
    dictionary key has leaked it just as thoroughly as one holding it as a value.
    """
    if isinstance(payload, str):
        return redact(payload, names=names)
    if isinstance(payload, dict):
        return {
            redact(str(key), names=names): redact_payload(value, names=names)
            for key, value in payload.items()
        }
    if isinstance(payload, (list, tuple)):
        return [redact_payload(item, names=names) for item in payload]
    return payload


def wrap_untrusted(text: str) -> str:
    """Fence transcript content before it reaches any tool that reads it (C-25).

    The markers are stripped from the content before the fence is applied. A
    caller who reads the closing marker aloud otherwise closes the block early,
    and everything after it is read as instructions by whatever is downstream —
    which is the second-order injection this exists to stop.
    """
    body = (text or "").replace(UNTRUSTED_CLOSE, _DELIMITER_STRIPPED)
    body = body.replace(UNTRUSTED_OPEN, _DELIMITER_STRIPPED)
    return f"{UNTRUSTED_OPEN}\n{body}\n{UNTRUSTED_CLOSE}"


def contains_untrusted_marker(text: str) -> bool:
    return UNTRUSTED_OPEN in (text or "") or UNTRUSTED_CLOSE in (text or "")


__all__ = [
    "REDACTED_DATE",
    "REDACTED_DIGITS",
    "REDACTED_NAME",
    "UNTRUSTED_CLOSE",
    "UNTRUSTED_OPEN",
    "contains_untrusted_marker",
    "redact",
    "redact_payload",
    "wrap_untrusted",
]
