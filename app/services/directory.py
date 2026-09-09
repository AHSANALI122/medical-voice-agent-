"""Doctor resolution against an in-memory whitelist (C-11, C-35).

Free text from speech never reaches SQL. The directory is loaded once at boot
into a plain Python list, and a spoken doctor or specialty is resolved against
that list in memory. An injection payload spoken as a doctor name therefore
matches nothing — it does not error, and it never becomes a query.

Ambiguity asks. This module returns candidates; it never picks one.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.models import Doctor
from app.security.normalize import normalize_name


@dataclass(frozen=True)
class DirectoryEntry:
    doctor_id: int
    full_name: str
    specialty: str
    normalized_name: str
    normalized_specialty: str


_whitelist: list[DirectoryEntry] = []


def load_whitelist(db: OrmSession) -> list[DirectoryEntry]:
    global _whitelist
    rows = (
        db.execute(select(Doctor).where(Doctor.active.is_(True)).order_by(Doctor.id))
        .scalars()
        .all()
    )
    _whitelist = [
        DirectoryEntry(
            doctor_id=d.id,
            full_name=d.full_name,
            specialty=d.specialty,
            normalized_name=normalize_name(d.full_name),
            normalized_specialty=normalize_name(d.specialty),
        )
        for d in rows
    ]
    return _whitelist


def whitelist() -> list[DirectoryEntry]:
    return list(_whitelist)


def search(*, specialty: str | None = None, doctor_query: str | None = None) -> list[DirectoryEntry]:
    """Candidates matching a spoken specialty or doctor name.

    Substring matching over normalized forms, in memory. Returns everything that
    matches; the caller decides whether that is one answer or a question.
    """
    entries = whitelist()
    if specialty:
        needle = normalize_name(specialty)
        if not needle:
            return []
        entries = [e for e in entries if needle in e.normalized_specialty]
    if doctor_query:
        needle = normalize_name(doctor_query)
        if not needle:
            return []
        # "doctor ahmed" and "dr ahmed" both reduce to a search for "ahmed".
        needle = " ".join(t for t in needle.split() if t not in {"dr", "doctor"})
        if not needle:
            return []
        entries = [e for e in entries if needle in e.normalized_name]
    return entries
