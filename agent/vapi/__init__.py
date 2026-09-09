"""The phone channel (F13).

Same tools as the web channel, its own channel secret, outbound calling absent
rather than restricted, and a duration cap set here as well as enforced by the
server.
"""

from agent.vapi.assistant import MAX_DURATION_SECONDS, build_assistant
from agent.vapi.webhook import (
    ALLOWED_ARGUMENTS,
    UnauthenticatedWebhook,
    VapiBridge,
    parse_tool_calls,
    verify_signature,
)

__all__ = [
    "ALLOWED_ARGUMENTS",
    "MAX_DURATION_SECONDS",
    "UnauthenticatedWebhook",
    "VapiBridge",
    "build_assistant",
    "parse_tool_calls",
    "verify_signature",
]
