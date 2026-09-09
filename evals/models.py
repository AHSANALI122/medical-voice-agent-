"""The eval vocabulary (F11).

A scenario is data, not code, and that is the point. Twenty-five conversations
written as a list of steps can be read end to end by somebody deciding whether
the attacks are real ones; twenty-five hand-written test functions cannot.

Each scenario ends in an assertion about the **database**, not about what the
agent said. What an agent says is the least trustworthy thing in this system —
section 8 assumes the model can be talked into saying anything. What survives in
`appointments` and `audit_events` is the thing an attack either changed or
did not.

`caller` on a step is the untrusted half: it is what a person said out loud. It
is carried so the report can show what the attack sounded like, and it is fenced
by `app.security.redaction.wrap_untrusted` before it reaches any tool that reads
it (C-25). It is never sent to the API — the API takes arguments, not speech.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

HAPPY = "happy"
ADVERSARIAL = "adversarial"


@dataclass(frozen=True)
class Step:
    """One tool call, and the utterance that would have produced it.

    `arguments` may hold placeholders: a value of exactly `"$name"` is replaced
    by the variable `name` with its type intact, and `"${name}"` inside a longer
    string is interpolated. Variables come from `capture` on earlier steps.
    """

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    caller: str | None = None
    channel: str | None = None
    expect_status: int = 200
    # Response fields that must equal these values. Placeholders allowed.
    expect: dict[str, Any] = field(default_factory=dict)
    # Response fields that must be present and truthy.
    expect_present: tuple[str, ...] = ()
    # Strings (or placeholders) that must not appear anywhere in the raw body.
    expect_absent: tuple[str, ...] = ()
    # {"variable": "response_field"} or {"variable": "response_field:date"}.
    capture: dict[str, str] = field(default_factory=dict)
    # Repeat this step n times. Used by the brute-force scenario so the script
    # reads as "five wrong guesses" rather than as five copy-pasted steps.
    repeat: int = 1


@dataclass(frozen=True)
class FinalState:
    """What must be true of the database once the conversation ends."""

    active: int = 0
    cancelled: int = 0
    # None means "do not assert" — some scenarios legitimately create a patient
    # row per booking attempt and the count is not the interesting fact.
    patients: int | None = None
    escalations: int = 0
    # (action, decision, reason, minimum count). A minimum rather than an exact
    # count because the interesting claim is "the trail exists", and pinning an
    # exact number would make every scenario brittle against an added audit row.
    audit_at_least: tuple[tuple[str, str, str, int], ...] = ()
    # Every captured reference must be absent from every column of every table.
    # Asserted on all twenty-five, because the one place a reference must never
    # reach is storage (5.1).
    no_stored_reference: bool = True


@dataclass(frozen=True)
class Scenario:
    name: str
    kind: str
    summary: str
    steps: tuple[Step, ...]
    final: FinalState
    # The findings this conversation is evidence for. Empty for happy paths.
    findings: tuple[str, ...] = ()

    @property
    def is_attack(self) -> bool:
        return self.kind == ADVERSARIAL

    @property
    def transcript(self) -> tuple[str, ...]:
        return tuple(step.caller for step in self.steps if step.caller)


@dataclass
class StepResult:
    tool: str
    status_code: int
    passed: bool
    detail: str | None = None


@dataclass
class ScenarioResult:
    scenario: Scenario
    steps: list[StepResult] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures
