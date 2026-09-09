"""The web channel's transport (F12).

Pipecat runs in this process, server-side, and holds the provider keys. The
browser holds a room id and a sixty-second token, which is the whole of what it
is trusted with.
"""

from agent.pipecat.pipeline import (
    PROVIDER_KEY_VARIABLES,
    PipecatUnavailable,
    PipelineConfig,
    build_pipeline,
    missing_provider_keys,
    tool_client_for,
)

__all__ = [
    "PROVIDER_KEY_VARIABLES",
    "PipecatUnavailable",
    "PipelineConfig",
    "build_pipeline",
    "missing_provider_keys",
    "tool_client_for",
]
