"""Audit-event display for the tester (F9).

F9 asks the tester to show the audit events a conversation generated, and F9's
acceptance says no endpoint may be reachable by the tester and not by the voice
channels. Those two pull in opposite directions: an `/audit` endpoint built for
the tester would be exactly the extra surface the acceptance criterion forbids,
and C-13 is the finding about the tester becoming a backdoor.

So the tester reads the audit table directly, over a **read-only** SQLite
connection, and only the non-PHI columns. That adds no endpoint, grants no
authority, and cannot mutate anything — `mode=ro` is enforced by SQLite, not by
this module's good intentions. It is a development tool looking at a development
database, and it refuses to run in production at all (see `guard.py`).

The query is a constant with bound parameters. No caller text reaches it.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

# Only the columns that carry no patient data. `audit_events` has no name and no
# reference column by design, and `detail` is documented as non-PHI context, but
# naming the columns explicitly means a future column cannot leak in by being
# added to the table.
_QUERY = (
    "SELECT id, created_at, session_id, channel, action, "
    "target_appointment_id, decision, reason, detail "
    "FROM audit_events ORDER BY id DESC LIMIT ?"
)


@dataclass(frozen=True)
class AuditRow:
    id: int
    created_at: str
    session_id: str | None
    channel: str | None
    action: str
    target_appointment_id: int | None
    decision: str
    reason: str
    detail: str | None


class AuditUnavailable(RuntimeError):
    """The database file is not readable from here — an in-memory database, or
    an API running on another machine. Not an error worth crashing the panel for.
    """


def database_path(environ: dict[str, str] | None = None) -> str:
    source = environ if environ is not None else os.environ
    return source.get("VB_DATABASE_PATH") or "data/voicebook.db"


def read_events(limit: int = 25, path: str | None = None) -> list[AuditRow]:
    path = path or database_path()
    if path == ":memory:" or not Path(path).exists():
        raise AuditUnavailable(
            f"No readable database at {path!r}. The audit panel needs the API to be "
            "using a file-backed database on this machine."
        )

    # mode=ro is the control. A tester that cannot write cannot be talked into
    # writing, whatever the code around it does later.
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rows = connection.execute(_QUERY, (limit,)).fetchall()
    finally:
        connection.close()

    return [AuditRow(*row) for row in rows]
