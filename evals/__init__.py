"""The eval suite (F11).

Twenty-five scripted conversations, fifteen happy and ten adversarial, each
ending in an assertion about the database. `tests/adversarial/test_f11_evals.py`
runs them, so they gate CI the way spec F11 requires.

This package is a test harness, not an untrusted client, and the distinction is
deliberate. It drives the API over the same signed HTTP path any caller uses —
it has no privileged endpoint — but it *does* read the database directly to
check where a conversation landed. An eval that asserted only on responses would
be asserting on the agent's own account of what it did, and section 8 is
explicit that the agent's account is the thing not to believe.

`agent/` and `tester/` are the packages the import-boundary check governs. This
one is not among them, on purpose.
"""

from evals.models import ADVERSARIAL, HAPPY, Scenario, ScenarioResult, Step
from evals.runner import run
from evals.scenarios import ADVERSARIAL_SCENARIOS, ALL_SCENARIOS, HAPPY_SCENARIOS

__all__ = [
    "ADVERSARIAL",
    "ADVERSARIAL_SCENARIOS",
    "ALL_SCENARIOS",
    "HAPPY",
    "HAPPY_SCENARIOS",
    "Scenario",
    "ScenarioResult",
    "Step",
    "run",
]
