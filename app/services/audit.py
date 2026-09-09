"""Audit writes (F17, C-28).

One rule: the row is added to the same SQLAlchemy session as the mutation it
records, and never committed separately. A rolled-back mutation therefore leaves
no audit row, and a committed one always leaves exactly one.

There is no update and no delete path in this module, and none anywhere else.
"""

from __future__ import annotations

from sqlalchemy.orm import Session as OrmSession

from app.models import AuditEvent


def record(
    db: OrmSession,
    *,
    action: str,
    decision: str,
    reason: str,
    session_id: str | None = None,
    channel: str | None = None,
    target_appointment_id: int | None = None,
    detail: str | None = None,
) -> AuditEvent:
    """Append one event. `detail` carries non-PHI context only: never a name,
    never a reference, never symptom text.
    """
    event = AuditEvent(
        session_id=session_id,
        channel=channel,
        action=action,
        target_appointment_id=target_appointment_id,
        decision=decision,
        reason=reason,
        detail=detail,
    )
    db.add(event)
    return event
