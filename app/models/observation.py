from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UtcDateTime, utcnow

# Outcomes. A closed vocabulary, mapped from the response status, so nothing a
# caller controls ever reaches this column as free text.
OUTCOME_OK = "ok"
OUTCOME_INVALID = "invalid"
OUTCOME_UNAUTHENTICATED = "unauthenticated"
OUTCOME_DENIED = "denied"
OUTCOME_CONFLICT = "conflict"
OUTCOME_THROTTLED = "throttled"
OUTCOME_NOT_FOUND = "not_found"
OUTCOME_ERROR = "error"
OUTCOME_ESCALATED = "escalated"

UNKNOWN_TOOL = "unknown"


class ObservabilityEvent(Base):
    """One row per tool call (F11).

    Deliberately has no free-text column, and that is the whole design rather
    than an omission. C-09 calls transcripts an unbounded PHI sink; the answer
    here is not to redact a transcript column carefully, it is to have no column
    a transcript could be written to. Every field below is either a
    server-minted opaque token, a value from a closed set, or a number.

    Separate from `audit_events` on purpose. Audit rows are append-only and
    permanent (F17) because they record who was allowed to mutate what. These
    rows are operational telemetry, they are purged at 30 days, and they must be
    deletable — putting them in the same table would mean either an audit trail
    with a delete path or telemetry that can never be purged.
    """

    __tablename__ = "observability_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Server-minted per request. The one value a caller can quote back when
    # something failed, and it identifies nothing about them.
    correlation_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Opaque token from `secrets`, carrying no patient data and no tier (C-38).
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    channel: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Constrained to the published tool surface before it is written; anything
    # else is stored as UNKNOWN_TOOL, because the path segment is caller-chosen.
    tool: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    turn: Mapped[int | None] = mapped_column(Integer, nullable=True)

    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    escalated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow, index=True
    )
