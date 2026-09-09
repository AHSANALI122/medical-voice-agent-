"""The per-request observation carrier (F11).

A leaf module on purpose: standard library only, no models, no services, no
security. Both the security layer and the service layer stamp fields onto an
observation, and neither may end up importing the other to do it.

Why an object on `request.state` rather than a context variable: sync endpoints
run in a worker thread, and anyio copies the context *into* that thread. A
contextvar set inside a handler is therefore invisible to the middleware that
would read it afterwards. The same mutable object either side of the hop is not.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

OBSERVATION_ATTR = "vb_observation"


@dataclass
class Observation:
    """What one request accumulated on its way through.

    Every field is either server-minted or drawn from a closed set. There is no
    field for caller speech, and adding one would be the change that turns this
    into the unbounded PHI sink C-09 is about.
    """

    correlation_id: str = field(default_factory=lambda: secrets.token_hex(16))
    channel: str | None = None
    session_id: str | None = None
    turn: int | None = None
    escalated: bool = False


def observation(request) -> Observation:
    """Get, or create, this request's observation."""
    existing = getattr(request.state, OBSERVATION_ATTR, None)
    if existing is None:
        existing = Observation()
        setattr(request.state, OBSERVATION_ATTR, existing)
    return existing


def stamp(request, **fields) -> None:
    """Record what a dependency or a handler learned. Never raises.

    Called from the authentication and authorization layers, which have to keep
    working whether or not telemetry does. A metrics failure is not permitted to
    become an authentication failure.
    """
    try:
        current = observation(request)
    except Exception:  # pragma: no cover - a request with no usable state
        return
    for key, value in fields.items():
        if hasattr(current, key):
            setattr(current, key, value)
