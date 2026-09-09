"""The voice layer (F12, F13).

A microphone and a speaker. No business logic, no authority, no access decision
lives in this package. If a rule about who may do what appears anywhere under
`agent/`, it is in the wrong file.

The only thing here that touches the application is `agent.client`, which speaks
HTTP with the same signature any external caller computes. Nothing in this
package imports `app.services`, `app.db`, `app.models`, `app.security` or
`app.tools`, and `scripts/check_import_boundary.py` fails the build if that ever
changes (C-19). The boundary is a network hop, not a convention: one an import
can walk through is not a boundary at all.
"""

from agent import turn, vad
from agent.client import TOOLS, ToolClient, ToolResponse
from agent.prompts import SYSTEM_PROMPT, tool_declarations

__all__ = [
    "SYSTEM_PROMPT",
    "TOOLS",
    "ToolClient",
    "ToolResponse",
    "tool_declarations",
    "turn",
    "vad",
]
