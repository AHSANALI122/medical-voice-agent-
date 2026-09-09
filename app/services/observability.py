"""Structured events, and the 30-day purge (F11 — C-09).

One row per `/tools/*` call: which session, which turn, which tool, how long it
took, what the outcome was, and whether the turn escalated. That list is the
whole event vocabulary from spec F11, and it is deliberately the whole of it —
there is no field here for what the caller said.

Three rules this module holds.

**Telemetry never rides the mutation's transaction.** The opposite of the audit
rule (F17), and for the opposite reason. An audit row must be lost if its
mutation rolls back. An event row must not be able to roll a mutation back, so
it is written on its own session, after the response is built, and a failure to
write one is swallowed. A booking that succeeded must not be undone because a
metrics insert hit a locked table.

**Every stored string comes from a closed set or is server-minted.** The tool
name is checked against the published surface before it is written, because the
path segment is whatever the caller typed. Values still pass through `redact`
on the way in, which is belt and braces rather than the control: the control is
that no free text is collected.

**Purge is a real delete.** Thirty days, and the rows go. That is why these
events do not live in `audit_events`, which has no delete path anywhere.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from app.models import (
    OUTCOME_CONFLICT,
    OUTCOME_DENIED,
    OUTCOME_ERROR,
    OUTCOME_ESCALATED,
    OUTCOME_INVALID,
    OUTCOME_NOT_FOUND,
    OUTCOME_OK,
    OUTCOME_THROTTLED,
    OUTCOME_UNAUTHENTICATED,
    UNKNOWN_TOOL,
    ObservabilityEvent,
)
from app.observability import OBSERVATION_ATTR, Observation, observation, stamp
from app.security.redaction import redact

log = logging.getLogger("voicebook.events")

RETENTION_DAYS = 30

# The published tool surface. A path segment outside it is telemetry about a
# probe, and the probe does not get to choose what string lands in the column.
KNOWN_TOOLS: frozenset[str] = frozenset(
    {
        "create_session",
        "resolve_date",
        "screen_turn",
        "search_doctors",
        "get_available_slots",
        "book_appointment",
        "append_reference_digits",
        "clear_reference_digits",
        "cancel_appointment",
    }
)

_STATUS_OUTCOMES: dict[int, str] = {
    401: OUTCOME_UNAUTHENTICATED,
    403: OUTCOME_DENIED,
    404: OUTCOME_NOT_FOUND,
    409: OUTCOME_CONFLICT,
    422: OUTCOME_INVALID,
    429: OUTCOME_THROTTLED,
}


def tool_from_path(path: str) -> str:
    """Map a request path to a tool name from the published surface."""
    segment = path.rsplit("/", 1)[-1] if path else ""
    return segment if segment in KNOWN_TOOLS else UNKNOWN_TOOL


def outcome_for(status_code: int, *, escalated: bool = False) -> str:
    if escalated:
        return OUTCOME_ESCALATED
    if status_code in _STATUS_OUTCOMES:
        return _STATUS_OUTCOMES[status_code]
    if 200 <= status_code < 300:
        return OUTCOME_OK
    return OUTCOME_ERROR


def record_tool_call(
    db: OrmSession,
    *,
    correlation_id: str,
    tool: str,
    status_code: int,
    latency_ms: float,
    channel: str | None = None,
    session_id: str | None = None,
    turn: int | None = None,
    escalated: bool = False,
) -> ObservabilityEvent:
    """Append one event. The caller owns the transaction.

    `session_id` and `correlation_id` are not redacted, and that is intentional.
    Both are `secrets` tokens, so both will sometimes contain four consecutive
    digits by chance; redacting them corrupts the only two keys that join a
    conversation's events together, in exchange for hiding nothing. Neither
    identifies a patient and neither grants access to anything (C-38).

    Everything that *could* carry caller text is either absent from this table
    or drawn from a closed set. `channel` still goes through the redactor —
    belt and braces, not the control. The control is the schema.
    """
    event = ObservabilityEvent(
        correlation_id=correlation_id,
        session_id=session_id,
        channel=redact(channel) if channel else None,
        tool=tool if tool in KNOWN_TOOLS else UNKNOWN_TOOL,
        turn=turn,
        status_code=status_code,
        latency_ms=round(latency_ms, 3),
        outcome=outcome_for(status_code, escalated=escalated),
        escalated=escalated,
    )
    db.add(event)
    return event


def log_line(event: ObservabilityEvent) -> str:
    """The same event as one structured log line.

    JSON rather than a formatted message because a log an operator has to parse
    with a regex is a log nobody reads during an incident.
    """
    return json.dumps(
        {
            "event": "tool_call",
            "correlation_id": event.correlation_id,
            "session_id": event.session_id,
            "channel": event.channel,
            "tool": event.tool,
            "turn": event.turn,
            "status": event.status_code,
            "latency_ms": event.latency_ms,
            "outcome": event.outcome,
            "escalated": event.escalated,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def purge(db: OrmSession, *, older_than_days: int = RETENTION_DAYS, now: datetime | None = None) -> int:
    """Delete events older than the retention window (F11 acceptance).

    Returns the number removed. Only this table is purged: `audit_events` has no
    delete path in application code and this function does not become one.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=older_than_days)
    doomed = (
        db.execute(
            select(ObservabilityEvent.id).where(ObservabilityEvent.created_at < cutoff)
        )
        .scalars()
        .all()
    )
    if not doomed:
        return 0
    db.execute(delete(ObservabilityEvent).where(ObservabilityEvent.id.in_(doomed)))
    return len(doomed)


def summarize(db: OrmSession) -> dict[str, int]:
    """Counts by outcome. Used by the eval report and by nothing that decides."""
    rows = db.execute(select(ObservabilityEvent.outcome)).scalars().all()
    counts: dict[str, int] = {}
    for outcome in rows:
        counts[outcome] = counts.get(outcome, 0) + 1
    return counts


# Re-exported so the FastAPI layer has one import for everything telemetry:
# the carrier lives in `app.observability` precisely so that the security layer
# can stamp it without importing a service.
__all__ = [
    "KNOWN_TOOLS",
    "OBSERVATION_ATTR",
    "RETENTION_DAYS",
    "Observation",
    "log_line",
    "observation",
    "outcome_for",
    "purge",
    "record_tool_call",
    "stamp",
    "summarize",
    "tool_from_path",
]
