"""What a model is allowed to hand a tool, on any channel (C-04, F13).

This was in `agent/vapi/webhook.py`, which was the right place while the phone
was the only channel with a model attached to it. It is the wrong place now.
F13's acceptance asks for parity — the same scripted conversation producing the
same database state on web and phone — and two copies of an argument allowlist
is the most reliable way to lose that quietly: somebody widens one, the other
keeps refusing, and the conversation that proves parity is the conversation
nobody runs afterwards.

So both channels read this. It holds no credential, talks to nothing, and
decides nothing about authority; it is the list of words a compromised model may
put in front of the API, and the far more important list of what it may not.

Note what no entry contains: an identifier of any row in the database. The model
never names a patient id, an appointment id, or a doctor id, because it is never
given one. It says "the second one", and the server resolves that against the
list it itself offered (C-04).
"""

from __future__ import annotations

from typing import Any

# The complete argument surface, per tool. Anything outside it is dropped before
# a request exists rather than refused afterwards: a 422 tells a caller what the
# schema is, and dropping tells them nothing.
ALLOWED_ARGUMENTS: dict[str, frozenset[str]] = {
    "search_doctors": frozenset({"specialty", "doctor_query"}),
    "resolve_date": frozenset({"phrase", "for_cancellation"}),
    "get_available_slots": frozenset({"doctor_ordinal", "on_date"}),
    "book_appointment": frozenset({"slot_ordinal", "patient_name"}),
    "append_reference_digits": frozenset({"fragment"}),
    "clear_reference_digits": frozenset(),
    "cancel_appointment": frozenset({"patient_name", "appointment_date", "reference"}),
}

# Tools the server requires an idempotency key for, which the agent mints rather
# than accepting from the model. F15's key is what makes a retry safe, and a
# model-chosen one is a key an attacker chose.
NEEDS_IDEMPOTENCY_KEY = frozenset({"book_appointment"})

# Never accepted from a model on any channel, whatever the tool. `session_id` is
# the agent's to supply — a model that can pick one can pick somebody else's.
NEVER_FROM_THE_MODEL = frozenset({"session_id", "idempotency_key"})


def sanitize(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Keep what this tool is allowed to carry and silently drop the rest.

    Silently on purpose. An error naming the rejected field would teach an
    injected utterance what to try next, and the model has no legitimate use for
    the knowledge: every argument it may send is one it was told about in the
    tool declaration it was given.
    """
    allowed = ALLOWED_ARGUMENTS.get(tool, frozenset())
    return {
        name: value
        for name, value in arguments.items()
        if name in allowed and name not in NEVER_FROM_THE_MODEL
    }


__all__ = [
    "ALLOWED_ARGUMENTS",
    "NEEDS_IDEMPOTENCY_KEY",
    "NEVER_FROM_THE_MODEL",
    "sanitize",
]
