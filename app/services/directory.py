"""Doctor and specialty resolution (F6 — C-11, C-35).

Free text from speech never reaches SQL. The directory is loaded once at boot
into a plain Python list, and a spoken doctor or specialty is resolved against
that list in memory. An injection payload spoken as a doctor name therefore
matches nothing: it does not error, and it never becomes a query. There is no
code path from this module to a WHERE clause built out of caller text.

**Ambiguity asks; it never auto-selects.** Matching runs in tiers — exact, then
token, then substring, then phonetic — and the *first* tier that produces any
candidate wins outright. Tiers are never merged, so a phonetic guess can never
outvote or dilute an exact hit. Whatever that tier produces is returned as-is: a
single candidate resolves, two or more is a question for the caller, and this
module never picks between them.

Phonetic matching exists because "Ahmad" and "Ahmed" are one person to a human
and two strings to a computer (C-35). It widens the candidate set and nothing
else. It has one useful side effect worth naming: the phonetic tier requires
*every* token of the query to match something, so an injection payload — which
is mostly tokens no doctor's name contains — falls out on its own rather than
being rescued by the one word in it that happens to sound like a surname.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.models import Doctor
from app.security.normalize import normalize_name

# Titles a caller says out of politeness. They carry no identifying information
# and every doctor has one, so they are stripped from both sides of a match.
HONORIFICS = frozenset({"dr", "doctor", "prof", "professor"})


@dataclass(frozen=True)
class DirectoryEntry:
    doctor_id: int
    full_name: str
    specialty: str
    normalized_name: str
    normalized_specialty: str
    # The name with honorifics removed, which is what a caller actually says.
    bare_tokens: tuple[str, ...]
    name_codes: frozenset[str]
    specialty_codes: frozenset[str]


class Outcome(str, Enum):
    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    NO_MATCH = "no_match"


@dataclass(frozen=True)
class Resolution:
    """What the directory found. `entry` is populated only when exactly one
    candidate survived — the type makes auto-selecting impossible rather than
    merely discouraged.
    """

    outcome: Outcome
    candidates: tuple[DirectoryEntry, ...]
    matched_by: str

    @property
    def entry(self) -> DirectoryEntry | None:
        return self.candidates[0] if self.outcome is Outcome.RESOLVED else None


# --------------------------------------------------------------- phonetics

_SOUNDEX_CODES = {
    "b": "1", "f": "1", "p": "1", "v": "1",
    "c": "2", "g": "2", "j": "2", "k": "2", "q": "2", "s": "2", "x": "2", "z": "2",
    "d": "3", "t": "3",
    "l": "4",
    "m": "5", "n": "5",
    "r": "6",
}


def soundex(token: str) -> str:
    """Classic Soundex, four characters.

    Chosen over a fancier algorithm for one reason: it is thirty lines with no
    dependency and no model behind it, so it behaves identically on every
    machine and in every deployment. An accuracy gain that costs a package and a
    download is not a good trade for a widening heuristic that never decides
    anything on its own.
    """
    letters = [ch for ch in token.lower() if ch.isalpha()]
    if not letters:
        return ""

    codes = [_SOUNDEX_CODES.get(ch, "") for ch in letters]
    out = letters[0].upper()
    previous = codes[0]

    for letter, code in zip(letters[1:], codes[1:]):
        if code and code != previous:
            out += code
        # h and w are transparent: "Ashcroft" keeps its two distinct codes.
        if letter not in ("h", "w"):
            previous = code

    return (out + "000")[:4]


def _codes(tokens: tuple[str, ...]) -> frozenset[str]:
    return frozenset(soundex(t) for t in tokens if t)


def _tokens(text: str) -> tuple[str, ...]:
    return tuple(t for t in normalize_name(text).split() if t and t not in HONORIFICS)


# Below this, a fragment is not evidence of anything. Found the hard way: the
# normalized form of "' OR 1=1 --" is the single token "or", which is a substring
# of "orthopedics", so a bare substring test happily resolved an injection
# payload to a specialty. Harmless here — the list is in memory and nothing
# reached SQL — but resolving garbage to a real record is the shape of the bug
# that is not harmless somewhere else.
MIN_FRAGMENT = 4


def _prefix_match(needles: tuple[str, ...], haystack: tuple[str, ...]) -> bool:
    """Every needle token equals, or meaningfully prefixes, a haystack token."""
    for needle in needles:
        if not any(
            needle == token
            or (len(needle) >= MIN_FRAGMENT and token.startswith(needle))
            for token in haystack
        ):
            return False
    return bool(needles)


# -------------------------------------------------------------- whitelist


_whitelist: list[DirectoryEntry] = []


def load_whitelist(db: OrmSession) -> list[DirectoryEntry]:
    global _whitelist
    rows = (
        db.execute(select(Doctor).where(Doctor.active.is_(True)).order_by(Doctor.id))
        .scalars()
        .all()
    )
    _whitelist = []
    for d in rows:
        name_tokens = _tokens(d.full_name)
        specialty_tokens = _tokens(d.specialty)
        _whitelist.append(
            DirectoryEntry(
                doctor_id=d.id,
                full_name=d.full_name,
                specialty=d.specialty,
                normalized_name=normalize_name(d.full_name),
                normalized_specialty=normalize_name(d.specialty),
                bare_tokens=name_tokens,
                name_codes=_codes(name_tokens),
                specialty_codes=_codes(specialty_tokens),
            )
        )
    return _whitelist


def whitelist() -> list[DirectoryEntry]:
    return list(_whitelist)


# --------------------------------------------------------------- matching


def search(
    *, specialty: str | None = None, doctor_query: str | None = None
) -> list[DirectoryEntry]:
    """Literal candidates only: substring containment over normalized forms.

    Deliberately not phonetic. This is the strict path, and callers that want
    the widened one ask for it by name — so a payload that matches nothing here
    cannot be quietly rescued by a sound-alike.
    """
    entries = whitelist()
    if specialty:
        needles = _tokens(specialty)
        if not needles:
            return []
        entries = [
            e for e in entries if _prefix_match(needles, _tokens(e.normalized_specialty))
        ]
    if doctor_query:
        needle = " ".join(_tokens(doctor_query))
        if len(needle) < MIN_FRAGMENT:
            return []
        entries = [e for e in entries if needle in e.normalized_name]
    return entries


def _tiers(query_tokens: tuple[str, ...]) -> list[tuple[str, list[DirectoryEntry]]]:
    """Candidate sets in decreasing confidence. Never merged."""
    entries = whitelist()
    joined = " ".join(query_tokens)
    query_codes = _codes(query_tokens)

    exact = [e for e in entries if e.bare_tokens == query_tokens]

    token_subset = [
        e for e in entries if query_tokens and set(query_tokens) <= set(e.bare_tokens)
    ]

    substring = [
        e
        for e in entries
        if len(joined) >= MIN_FRAGMENT and joined in " ".join(e.bare_tokens)
    ]

    # Every token must sound like something in the name. A payload full of words
    # no doctor is called fails here even if one of its words rhymes.
    phonetic = [
        e
        for e in entries
        if query_codes and query_codes <= e.name_codes
    ]

    return [
        ("exact", exact),
        ("tokens", token_subset),
        ("substring", substring),
        ("phonetic", phonetic),
    ]


def resolve_doctor(query: str) -> Resolution:
    """Resolve a spoken doctor to at most one whitelist entry.

    Returns AMBIGUOUS rather than guessing whenever a tier yields more than one
    candidate. The caller asks; nothing here chooses.
    """
    query_tokens = _tokens(query)
    if not query_tokens:
        return Resolution(Outcome.NO_MATCH, (), "none")

    for name, candidates in _tiers(query_tokens):
        if not candidates:
            continue
        if len(candidates) == 1:
            return Resolution(Outcome.RESOLVED, tuple(candidates), name)
        return Resolution(Outcome.AMBIGUOUS, tuple(candidates), name)

    return Resolution(Outcome.NO_MATCH, (), "none")


def resolve_specialty(query: str) -> list[DirectoryEntry]:
    """Doctors practising a spoken specialty.

    A specialty naming several doctors is a list to offer, not an ambiguity to
    resolve — the caller picks a person, and picking is what the ordinal offer
    table is for. Phonetic widening is applied here too, so "cardiologist" finds
    Cardiology without a synonym table to maintain.
    """
    query_tokens = _tokens(query)
    if not query_tokens:
        return []

    literal = [
        e
        for e in whitelist()
        if _prefix_match(query_tokens, _tokens(e.normalized_specialty))
    ]
    if literal:
        return literal

    query_codes = _codes(query_tokens)
    return [e for e in whitelist() if query_codes and query_codes <= e.specialty_codes]
