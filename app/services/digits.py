"""Server-side digit buffer (F5, section 6.4, C-18).

VAD detects energy, not sentence completion. A caller who pauses between "four
seven" and "two nine" produces two turns, and no silence threshold fixes that
without making the agent sluggish.

So the buffer lives on the server and survives a cut turn. An early boundary
just means the next fragment appends. This is the project's standing move: do
not try to make an unreliable component reliable, design so its failures are
harmless.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.security.reference import REFERENCE_LENGTH

_NON_DIGITS = re.compile(r"\D+")

MAX_RETRIES = 2

# Spoken digits arrive as words about as often as numerals.
_WORD_DIGITS = {
    "zero": "0", "oh": "0", "o": "0", "nought": "0",
    "one": "1", "two": "2", "to": "2", "too": "2",
    "three": "3", "four": "4", "for": "4", "five": "5",
    "six": "6", "seven": "7", "eight": "8", "ate": "8", "nine": "9",
    "double": "", "triple": "",
}


@dataclass(frozen=True)
class BufferState:
    digits: str
    ready: bool
    overflowed: bool
    retries: int

    @property
    def readback(self) -> str | None:
        """Digit-by-digit readback, only once the buffer holds exactly four."""
        if not self.ready:
            return None
        return "-".join(self.digits)


def extract_digits(fragment: str) -> str:
    """Pull digits out of one spoken fragment.

    Numerals win; number words are translated. Anything else is dropped rather
    than rejected, because a transcriber will happily insert "um" mid-code.
    """
    numerals = _NON_DIGITS.sub("", fragment)
    if numerals:
        return numerals
    out = []
    for token in re.split(r"[^a-zA-Z]+", fragment.lower()):
        if token in _WORD_DIGITS:
            out.append(_WORD_DIGITS[token])
    return "".join(out)


def append_fragment(buffer: str, fragment: str, *, retries: int = 0) -> BufferState:
    """Append a fragment to the buffer and report what the agent may do next."""
    combined = buffer + extract_digits(fragment)
    if len(combined) > REFERENCE_LENGTH:
        # More than four digits means the caller misspoke or the transcriber
        # doubled something. Truncating would silently accept a wrong code, so
        # clear and re-ask instead.
        return BufferState(digits="", ready=False, overflowed=True, retries=retries + 1)
    return BufferState(
        digits=combined,
        ready=len(combined) == REFERENCE_LENGTH,
        overflowed=False,
        retries=retries,
    )


def clear_buffer(retries: int) -> BufferState:
    """Caller said the readback was wrong. Two retries, then hand off."""
    return BufferState(digits="", ready=False, overflowed=False, retries=retries + 1)


def retries_exhausted(retries: int) -> bool:
    return retries > MAX_RETRIES
