from __future__ import annotations

from datetime import datetime

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UtcDateTime, utcnow

# Actions
ACTION_BOOK = "book_appointment"
ACTION_CANCEL = "cancel_appointment"

# Decisions
DECISION_ALLOWED = "allowed"
DECISION_DENIED = "denied"

# Denial reasons. Server-side vocabulary only. None of these strings is ever
# rendered to a caller, because every caller-facing failure is identical (6.2).
REASON_MATCH = "match"
REASON_NO_MATCH = "no_match"
REASON_AMBIGUOUS = "ambiguous_match"
REASON_LOCKED = "appointment_locked"
REASON_ALREADY_CANCELLED = "already_cancelled"
REASON_SLOT_TAKEN = "slot_taken"
REASON_IDEMPOTENT_REPLAY = "idempotent_replay"


class AuditEvent(Base):
    """Append-only (F17). No application code updates or deletes a row here."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    channel: Mapped[str | None] = mapped_column(String(16), nullable=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target_appointment_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(48), nullable=False)
    # Non-PHI context only. Never a name, never a reference, never symptom text.
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
