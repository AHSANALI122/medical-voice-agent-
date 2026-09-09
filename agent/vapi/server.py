"""The endpoint Vapi posts to (F13).

Deliberately a **separate** ASGI application from the FastAPI service, running
in the agent process. That is not tidiness — it is the trust boundary made
operational. If this route lived on `app`, the agent and the application would
share a process, and "the boundary is a network hop" would be a comment rather
than a fact. Here, this server holds the phone channel secret and talks to the
API over HTTP exactly as any external client does.

It is a small surface on purpose: one POST, no GET that reveals anything, no
route that lists a call, and a single uniform 401 for every rejection.

Starlette is imported lazily so `agent.vapi.webhook` — where all the logic that
matters lives — can be tested without a web framework in the environment.
"""

from __future__ import annotations

import logging
import os

from agent.env import load_local_env
from agent.vapi.webhook import UnauthenticatedWebhook, VapiBridge

log = logging.getLogger("voicebook.agent.vapi")

DEFAULT_API_URL = "http://127.0.0.1:8000"
WEBHOOK_PATH = "/vapi/tools"

# One body for every rejection. A bad signature, an unknown tool and a malformed
# envelope are indistinguishable from outside, the same way every caller-facing
# failure is (6.2).
UNAUTHENTICATED_BODY = {"error": "unauthenticated"}

# Vapi's own payloads are small. A cap here means a hostile poster cannot make
# this process read an arbitrary amount into memory before the signature check.
MAX_BODY_BYTES = 64 * 1024


def create_app(*, api_url: str | None = None, bridge: VapiBridge | None = None):
    """Build the webhook application.

    `bridge` is injectable so a test can hand in a known secret rather than
    reaching into the environment.
    """
    # This is a process entry point, and `uvicorn` puts no `.env` into the
    # environment. Without this the server starts fine and then refuses every
    # post with a 401 that reads like a signature problem and is not.
    load_local_env()

    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    resolved = api_url or os.environ.get("VB_API_URL", DEFAULT_API_URL)
    active = bridge or VapiBridge(base_url=resolved)

    async def tools(request):
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            # Refused before the signature check, because the signature check
            # is not the thing that should be reading an unbounded body.
            return JSONResponse(UNAUTHENTICATED_BODY, status_code=401)

        try:
            results = active.handle(raw, dict(request.headers))
        except UnauthenticatedWebhook:
            # Nothing about the payload is logged. It carries caller speech and
            # tool arguments, which is exactly the unbounded sink C-09 is about.
            log.warning("vapi_webhook_refused")
            return JSONResponse(UNAUTHENTICATED_BODY, status_code=401)
        except Exception:
            # C-30: a provider failure is an ordinary outcome. The model gets a
            # generic answer and the call continues rather than crashing.
            log.exception("vapi_webhook_failed")
            return JSONResponse({"error": "unavailable"}, status_code=503)

        return JSONResponse({"results": results})

    async def healthz(_request):
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route(WEBHOOK_PATH, tools, methods=["POST"]),
            Route("/healthz", healthz, methods=["GET"]),
        ]
    )


__all__ = ["DEFAULT_API_URL", "MAX_BODY_BYTES", "WEBHOOK_PATH", "create_app"]
