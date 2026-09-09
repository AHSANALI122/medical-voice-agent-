"""Runs a scenario against the tool API and checks where the database landed.

The runner is a **client**. It signs and posts exactly like Vapi would, through
whatever caller it is handed; it never reaches into a service to make something
happen. It does read the database directly, and that is the one privilege it
has — an eval that asserted only on responses would be asserting on the agent's
own account of what it did, which is the account section 8 says not to believe.

Nothing in a scenario reaches SQL. Arguments are posted as JSON to the published
endpoints, and the final-state checks are parameterized ORM queries.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import String, Text, select
from sqlalchemy.orm import Session as OrmSession

from app.models import (
    ACTION_ESCALATE,
    Appointment,
    AuditEvent,
    Base,
    Patient,
    STATUS_ACTIVE,
    STATUS_CANCELLED,
)
from evals.models import Scenario, ScenarioResult, Step, StepResult

_PLACEHOLDER = re.compile(r"\$\{(\w+)\}")


class Caller(Protocol):
    """Anything that can post a signed request. The tests pass the same signed
    client the contract suite uses; `python -m evals` builds one over a
    TestClient. Neither gets a privileged path (C-13).
    """

    def post(self, path: str, payload: dict, *, channel: str | None = ...) -> Any: ...


@dataclass
class Bag:
    """Variables captured as the conversation runs."""

    values: dict[str, Any]

    def resolve(self, value: Any) -> Any:
        if isinstance(value, str):
            if value.startswith("$") and not value.startswith("${"):
                name = value[1:]
                if name not in self.values:
                    raise KeyError(f"scenario referenced unset variable ${name}")
                return self.values[name]
            return _PLACEHOLDER.sub(lambda m: str(self.values[m.group(1)]), value)
        if isinstance(value, dict):
            return {key: self.resolve(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.resolve(item) for item in value]
        return value


def _fresh_variables() -> dict[str, Any]:
    # A fresh idempotency key per scenario run. Scenarios that want to exercise
    # a *retry* name the same variable twice rather than generating two.
    return {
        "key": str(uuid.uuid4()),
        "key2": str(uuid.uuid4()),
        "key3": str(uuid.uuid4()),
    }


def _capture(bag: Bag, step: Step, body: dict) -> None:
    for name, spec in step.capture.items():
        field, _, transform = spec.partition(":")
        raw = body.get(field)
        if transform == "date":
            raw = datetime.fromisoformat(str(raw)).date().isoformat()
        bag.values[name] = raw


def _check_step(result, step: Step, bag: Bag) -> list[str]:
    problems: list[str] = []
    if result.status_code != step.expect_status:
        problems.append(
            f"{step.tool}: expected {step.expect_status}, got {result.status_code} "
            f"({result.text[:160]})"
        )
        return problems

    try:
        body = result.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}

    for field, expected in step.expect.items():
        wanted = bag.resolve(expected)
        if body.get(field) != wanted:
            problems.append(f"{step.tool}.{field}: expected {wanted!r}, got {body.get(field)!r}")

    for field in step.expect_present:
        if not body.get(field):
            problems.append(f"{step.tool}.{field}: expected a value, got {body.get(field)!r}")

    for token in step.expect_absent:
        needle = str(bag.resolve(token))
        if needle and needle in result.text:
            problems.append(f"{step.tool}: response leaked {token}")

    if step.capture:
        _capture(bag, step, body)
    return problems


# Columns whose contents are opaque by construction: HMAC digests and
# `secrets` tokens. A four-digit string turns up inside sixty-four hex
# characters often enough that including them would make this check noise
# rather than signal, and a digest is not a place a plaintext reference could
# hide anyway — it is the output of a one-way function over something else.
# `idempotency_key` is skipped for the same reason: it is built from a session
# token and a UUID, and `tests/adversarial/test_f15_idempotency.py` asserts
# separately that no reference reaches it.
_OPAQUE_COLUMNS: frozenset[tuple[str, str]] = frozenset(
    {
        ("rate_limit_buckets", "bucket_key"),
        ("observability_events", "correlation_id"),
        ("observability_events", "session_id"),
        ("audit_events", "session_id"),
        ("appointments", "idempotency_key"),
        ("sessions", "id"),
    }
)


def _text_columns():
    """Every string-ish column in the schema, for the stored-reference sweep."""
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if (table.name, column.name) in _OPAQUE_COLUMNS:
                continue
            if isinstance(column.type, (String, Text)):
                yield table, column


def _stored_reference_leaks(db: OrmSession, references: list[str]) -> list[str]:
    """Is any issued reference sitting in any text column anywhere?

    A sweep of the whole schema rather than a check of the columns we expect to
    be risky. The columns we expect to be risky are the ones already handled;
    the finding worth catching is the column somebody adds next year.

    Matched on digit boundaries, because a four-digit code is short enough to
    turn up by coincidence inside an ISO timestamp. That is a real limit of the
    check and it is why the opaque columns above are excluded by name rather
    than by hoping the boundary rule is enough.
    """
    problems: list[str] = []
    if not references:
        return problems
    patterns = [(ref, re.compile(rf"(?<![0-9]){re.escape(ref)}(?![0-9])")) for ref in references]
    for table, column in _text_columns():
        values = db.execute(select(column).where(column.isnot(None))).scalars().all()
        for value in values:
            text = str(value)
            for reference, pattern in patterns:
                if pattern.search(text):
                    problems.append(
                        f"reference {reference} found in "
                        f"{table.name}.{column.name}: {text!r}"
                    )
    return problems


def _check_final(db: OrmSession, scenario: Scenario, bag: Bag) -> list[str]:
    problems: list[str] = []
    want = scenario.final

    active = len(
        db.execute(select(Appointment.id).where(Appointment.status == STATUS_ACTIVE))
        .scalars()
        .all()
    )
    cancelled = len(
        db.execute(select(Appointment.id).where(Appointment.status == STATUS_CANCELLED))
        .scalars()
        .all()
    )
    if active != want.active:
        problems.append(f"active appointments: expected {want.active}, found {active}")
    if cancelled != want.cancelled:
        problems.append(f"cancelled appointments: expected {want.cancelled}, found {cancelled}")

    if want.patients is not None:
        patients = len(db.execute(select(Patient.id)).scalars().all())
        if patients != want.patients:
            problems.append(f"patients: expected {want.patients}, found {patients}")

    escalations = len(
        db.execute(select(AuditEvent.id).where(AuditEvent.action == ACTION_ESCALATE))
        .scalars()
        .all()
    )
    if escalations != want.escalations:
        problems.append(f"escalations: expected {want.escalations}, found {escalations}")

    for action, decision, reason, minimum in want.audit_at_least:
        found = len(
            db.execute(
                select(AuditEvent.id)
                .where(AuditEvent.action == action)
                .where(AuditEvent.decision == decision)
                .where(AuditEvent.reason == reason)
            )
            .scalars()
            .all()
        )
        if found < minimum:
            problems.append(
                f"audit {action}/{decision}/{reason}: expected at least {minimum}, found {found}"
            )

    if want.no_stored_reference:
        # Only the references themselves. `reference_date` is a captured date
        # and sweeping for it would flag every ISO timestamp in the schema.
        references = [
            str(value)
            for name, value in bag.values.items()
            if name.startswith("reference")
            and not name.endswith("_date")
            and isinstance(value, str)
            and value.isdigit()
        ]
        problems.extend(_stored_reference_leaks(db, references))

    return problems


def run(scenario: Scenario, *, caller: Caller, db: OrmSession) -> ScenarioResult:
    """Drive one conversation, then look at what the database says happened."""
    outcome = ScenarioResult(scenario=scenario)
    bag = Bag(values=_fresh_variables())

    for step in scenario.steps:
        for _ in range(step.repeat):
            payload = bag.resolve(step.arguments)
            kwargs = {"channel": step.channel} if step.channel else {}
            response = caller.post(f"/tools/{step.tool}", payload, **kwargs)

            problems = _check_step(response, step, bag)
            outcome.steps.append(
                StepResult(
                    tool=step.tool,
                    status_code=response.status_code,
                    passed=not problems,
                    detail="; ".join(problems) or None,
                )
            )
            outcome.failures.extend(problems)

    db.expire_all()
    outcome.failures.extend(_check_final(db, scenario, bag))
    return outcome
