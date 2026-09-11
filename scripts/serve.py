"""Start one of the three processes, with the one flag nobody may forget.

`uvicorn` enables `--proxy-headers` by default, and with it on, uvicorn rewrites
`request.client.host` from the caller's own `X-Forwarded-For` before the
application sees the request. That is not a small default. `client_ip` in
`app/security/request_auth.py` exists specifically to read that header carefully
— only as far back as the number of proxies actually in front of the service,
and not at all when there are none — because the header is a list the client can
write into. Uvicorn's version reads the leftmost entry, which is precisely the
one a client controls.

The effect, measured: a caller sending a different `X-Forwarded-For` on each
request gets a different rate-limit bucket each time. Every budget keyed on the
source address becomes decorative, which is the exact failure C-34 is about —
"an attacker who can pick their own key has no budget at all".

So the fix is not a flag in a runbook. A flag in a runbook is something you
remember on a good day. This is the entry point, it passes `proxy_headers=False`
itself, and `scripts/check_proxy_headers.py` fails the build if any other way of
starting a server in this repository leaves the default on.

    uv run python scripts/serve.py api      # the trusted zone
    uv run python scripts/serve.py phone    # what Vapi posts to
    uv run python scripts/serve.py web      # what a browser connects to

X-Forwarded-For is still honoured when there really is a proxy in front: set
`VB_TRUSTED_PROXY_HOPS` to the number of hops and `client_ip` reads it, with the
hop counting intact. The point is that one place decides, and it is the place
that was written to think about it.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"

# Running this as `python scripts/serve.py` puts `scripts/` on `sys.path`, not
# the repository root, and `app` and `agent` are then unimportable — uvicorn
# resolves its target by string, so the failure arrives as a bare
# `ModuleNotFoundError: No module named 'app'` from inside the importer. The
# uvicorn CLI does the same insertion for the working directory; this does it
# for the one directory that is always correct regardless of where it is run
# from.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass(frozen=True)
class Service:
    target: str
    port: int
    factory: bool
    description: str


SERVICES: dict[str, Service] = {
    "api": Service(
        target="app.main:app",
        port=8000,
        factory=False,
        description="FastAPI — the only trusted zone",
    ),
    "phone": Service(
        target="agent.vapi.server:create_app",
        port=8001,
        factory=True,
        description="the Vapi webhook (F13)",
    ),
    "web": Service(
        target="agent.pipecat.server:create_app",
        port=8002,
        factory=True,
        description="the browser's page and signalling (F12)",
    ),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Start one VoiceBook process with proxy headers disabled."
    )
    parser.add_argument(
        "service",
        choices=sorted(SERVICES),
        help="; ".join(f"{name}: {svc.description}" for name, svc in SERVICES.items()),
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument(
        "--check",
        action="store_true",
        help="resolve the target and exit without binding a port",
    )
    args = parser.parse_args(argv)

    service = SERVICES[args.service]

    # Resolved here rather than inside uvicorn's importer, so a path problem
    # says what it is instead of arriving as a ModuleNotFoundError from four
    # frames down.
    module_name = service.target.split(":", 1)[0]
    if importlib.util.find_spec(module_name) is None:
        print(
            f"cannot import {module_name!r} from {ROOT}. "
            f"Run this from a checkout, with `uv run python scripts/serve.py "
            f"{args.service}`.",
            file=sys.stderr,
        )
        return 2

    if args.check:
        print(f"{args.service}: {service.target} resolves; port {args.port or service.port}")
        return 0

    import uvicorn

    uvicorn.run(
        service.target,
        host=args.host,
        port=args.port or service.port,
        factory=service.factory,
        reload=args.reload,
        # The whole reason this file exists. Never make this a flag, an
        # environment variable or an argument: every one of those is a way for
        # it to be true on the machine where it was tested and false on the one
        # that is running.
        proxy_headers=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
