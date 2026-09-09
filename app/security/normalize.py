"""Name normalization (C-35).

The name arrives from speech-to-text and is load-bearing for record resolution.
Normalization exists so that "Ahmad" and "Ahmed  Khan " land on the same
matching key, and so that the value used in a query is drawn from a closed
character set rather than from whatever the transcriber produced.

This module does not query anything and does not decide anything. It maps a
string to a string.
"""

from __future__ import annotations

import re
import unicodedata

# The normalized alphabet: lowercase ASCII letters and single spaces. Anything
# else has already been rejected by the PatientName type before reaching here;
# stripping again is belt and braces, not the control.
_ALLOWED = re.compile(r"[^a-z ]")
_WHITESPACE = re.compile(r"\s+")


def normalize_name(raw: str) -> str:
    """Case-fold, strip diacritics, collapse whitespace, drop punctuation."""
    decomposed = unicodedata.normalize("NFKD", raw)
    without_marks = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    folded = without_marks.casefold()
    # Hyphens and apostrophes join name parts; treat them as separators so
    # "Al-Rashid" and "Al Rashid" normalize alike.
    spaced = folded.replace("-", " ").replace("'", "").replace("’", "")
    filtered = _ALLOWED.sub(" ", spaced)
    return _WHITESPACE.sub(" ", filtered).strip()
