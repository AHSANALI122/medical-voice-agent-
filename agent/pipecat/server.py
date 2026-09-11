"""The web channel's signalling server (F12 — C-19, C-16, C-27, C-30).

A **separate** ASGI application from the FastAPI service, for the same reason
`agent/vapi/server.py` is one: if this lived on `app`, the agent and the
application would share a process and "the boundary is a network hop" would be a
comment rather than a fact. Three processes, three jobs:

    app.main            :8000   the trusted zone
    agent.vapi.server   :8001   what Vapi posts to
    agent.pipecat.server:8002   what a browser connects to

This one serves the page, the WebRTC offer that turns a page into a call, and —
because a page and its API must share an origin — a closed two-entry passthrough
to the application endpoints the browser needs before a call exists at all.

It resolves no appointment, matches no reference, reads no database and holds no
room token key. Everything it is asked to decide, it asks the API.

Starlette is imported lazily so the policy in this package stays testable in an
environment with no web framework and no audio stack.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import httpx

from agent.env import NEVER_LOAD, load_local_env
from agent.pipecat.budget import OfferBudget
from agent.pipecat.pipeline import PipecatUnavailable, PipelineConfig, start_call
from agent.pipecat.rooms import MAX_ROOM_LENGTH, MAX_TOKEN_LENGTH, verify_room_token

log = logging.getLogger("voicebook.agent.web")

DEFAULT_API_URL = "http://127.0.0.1:8000"
OFFER_PATH = "/api/offer"

WEB_ROOT = Path(__file__).resolve().parent / "web"
INDEX = WEB_ROOT / "index.html"

# An SDP offer is a few kilobytes. The cap is what stops a stranger making this
# process read an unbounded body before anything has been verified.
MAX_BODY_BYTES = 64 * 1024

# The application is on the same machine. A browser waiting on a token has a
# person attached to it, so this fails fast rather than hanging the page.
PASSTHROUGH_TIMEOUT = 4.0

# One body for every refusal. Expired, tampered, wrong room, malformed envelope
# and unknown room are indistinguishable from outside (6.2).
REFUSED_BODY = {"error": "room token refused"}
UNAVAILABLE_BODY = {"error": "unavailable"}

# One body for every budget, whichever one it was. The page turns this into
# "The demo is busy right now" — the same words it already uses for the
# application's uniform 429 on minting.
BUSY_BODY = {"error": "busy"}

# Least privilege per process, enforced at the point the environment is read.
#
# This is the process a browser talks to, so it gets the web channel secret and
# the provider keys the pipeline needs, and nothing else that happens to be
# sitting in `.env`. `VB_ROOM_TOKEN_KEY` is on the list deliberately: without it
# this process *cannot* verify a room token locally even if somebody later
# writes the code to try, which turns the design in `rooms.py` from a convention
# into a fact. The phone and tester channel secrets are here because a room
# cannot be opened with them and a compromise of this process should not hand
# over the other two channels.
WEB_SERVER_NEVER_LOAD: frozenset[str] = NEVER_LOAD | frozenset(
    {
        "VB_ENCRYPTION_KEY",
        "VB_REFERENCE_HMAC_KEY",
        "VB_ROOM_TOKEN_KEY",
        "VB_VAPI_WEBHOOK_SECRET",
        "VB_CHANNEL_SECRET_PHONE",
        "VB_CHANNEL_SECRET_TESTER",
    }
)

# The page talks to its own origin and nowhere else. `check_client_bundle.py`
# greps for a cross-origin request at build time; this is the same rule enforced
# at run time by the browser, which is the half a grep cannot do. `unsafe-inline`
# is needed because the page's script is inline — the value here is `connect-src`
# and `default-src`, not script hashing.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; "
    "media-src 'self' blob:; "
    "img-src 'self' data:; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

PAGE_HEADERS = {
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "permissions-policy": "microphone=(self), camera=(), geolocation=()",
}

# The two application endpoints a browser is allowed to reach, and the complete
# list of them (F12, C-16).
#
# A page and its API have to share an origin — the browser's own rules say so,
# `connect-src 'self'` above says so, and `check_client_bundle.py` fails the
# build over a cross-origin request. But the page is served by this process and
# those two endpoints live in the application, so something has to front them.
#
# What makes that safe is that this is a closed list rather than a path prefix.
# `/web/*` would have handed a browser `/web/room-token/verify`; `/tools/*` would
# have been catastrophic, because this process holds the web channel secret and
# a proxy that signs on a stranger's behalf *is* the browser holding that secret.
# Both of these are unauthenticated by design: one returns settings that contain
# no secret, the other mints a token the application itself budgets.
#
# Nothing here decides anything. It forwards, and the application answers.
BROWSER_PASSTHROUGH: tuple[tuple[str, str], ...] = (
    ("GET", "/web/config"),
    ("POST", "/web/room-token"),
)

# Read from the environment, not from `app.config` — that import is the boundary.
TRUSTED_PROXY_HOPS_VARIABLE = "VB_TRUSTED_PROXY_HOPS"


def create_app(
    *,
    api_url: str | None = None,
    http: "httpx.Client | None" = None,
    budget: OfferBudget | None = None,
):
    """Build the signalling application.

    `api_url`, `http` and `budget` are injectable so a test can point this at a
    running application, and at a known budget, without patching a library or
    reaching into the environment.
    """
    # `uvicorn` puts no `.env` into the environment. Without this the process
    # starts perfectly happily and then fails every verify with a 401 that reads
    # like a signature problem and is not.
    load_local_env(skip=WEB_SERVER_NEVER_LOAD)

    from starlette.applications import Starlette
    from starlette.concurrency import run_in_threadpool
    from starlette.responses import FileResponse, JSONResponse, Response
    from starlette.routing import Route

    resolved = api_url or os.environ.get("VB_API_URL", DEFAULT_API_URL)

    # One client for the life of the process: the application is a fixed
    # upstream on the same machine, and a fresh connection per browser request
    # is latency this demo has a 1200ms budget for.
    upstream = http or httpx.Client(base_url=resolved, timeout=PASSTHROUGH_TIMEOUT)

    # Per process, in memory. See `budget.py` for why it is not in the database.
    offers = budget or OfferBudget()

    if os.environ.get(TRUSTED_PROXY_HOPS_VARIABLE, "0") != "1":
        # Worth being loud about, because the symptom is silent. The room-token
        # budget keys on the caller's address (C-34). With this process in front
        # of the application and the application not reading the forwarded
        # address, every browser in the world shares one bucket: six mints a day
        # between all of them, and one visitor locks out the next.
        log.warning(
            "%s is not 1. The application will charge the room-token budget to "
            "this process's address instead of the browser's.",
            TRUSTED_PROXY_HOPS_VARIABLE,
        )

    async def page(_request):
        if not INDEX.exists():  # pragma: no cover - the file is in the repo
            return JSONResponse(UNAVAILABLE_BODY, status_code=503)
        return FileResponse(INDEX, media_type="text/html", headers=PAGE_HEADERS)

    async def offer(request):
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            # Refused before anything parses it, for the same reason the Vapi
            # webhook refuses before the signature check.
            return JSONResponse(REFUSED_BODY, status_code=403)

        try:
            payload = json.loads(raw)
            room = str(payload["room"])
            token = str(payload["token"])
            sdp = str(payload["sdp"])
            sdp_type = str(payload["type"])
            consent = payload["consent"]
        except (ValueError, KeyError, TypeError):
            return JSONResponse(REFUSED_BODY, status_code=403)

        if consent is not True:
            # C-27, carried rather than assumed. The browser is the only place
            # that can know whether a person agreed, because it is the only
            # place a microphone was asked for — and a spoken disclosure is not
            # consent on the web, since by the time it is spoken the microphone
            # is already live. An offer that does not carry it is not a call.
            log.info("offer_without_consent")
            return JSONResponse(REFUSED_BODY, status_code=403)

        if len(room) > MAX_ROOM_LENGTH or len(token) > MAX_TOKEN_LENGTH:
            return JSONResponse(REFUSED_BODY, status_code=403)

        # Before the token is verified, deliberately. Two reasons, and the
        # second is the one that matters: it costs the API nothing, and a 429
        # that arrived only after verification would tell a prober their token
        # was the good part. Everybody over the limit gets the same answer,
        # forged token or not.
        peer = request.client.host if request.client else ""
        verdict = offers.admit(client_ip=peer, room=room)
        if not verdict:
            log.info("offer_over_budget reason=%s", verdict.reason)
            return JSONResponse(BUSY_BODY, status_code=429)

        # The one decision on this path, and it is made by the API. Off the
        # event loop: this is a blocking HTTP call, and the loop it would block
        # is the one carrying everybody else's audio.
        check = await run_in_threadpool(
            verify_room_token, token=token, room=room, base_url=resolved, http=upstream
        )
        if not check.allowed:
            # Unreachable and refused get the same status. The browser learns
            # that it is not getting a call, and nothing about why: "the token
            # was fine but the booking system is down" is a sentence that tells
            # a prober their token is fine.
            log.info("offer_refused reachable=%s", check.reachable)
            return JSONResponse(REFUSED_BODY, status_code=403)

        config = PipelineConfig(
            room=check.room, room_token=token, base_url=resolved, channel="web"
        )

        def _released(closed):
            offers.release(room, closed)

        try:
            answer, connection = await start_call(
                config,
                sdp=sdp,
                sdp_type=sdp_type,
                consent_given=consent,
                on_closed=_released,
            )
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see below
            if not isinstance(exc, PipecatUnavailable):
                # An SDP is a stranger's string and it goes to a parser. A
                # malformed one came back as `ValueError: invalid literal for
                # int()` and escaped as a 500 — a crash, and worse, an oracle:
                # a caller who can tell 500 from 403 has learned their token was
                # the good part. Every way an offer can fail to become a call
                # now says the same thing the room token check says.
                log.exception("offer_failed")
                return JSONResponse(REFUSED_BODY, status_code=403)
            # C-30. The token was good and the call still cannot start — no
            # audio stack, or a provider key missing from this process. The
            # browser is told the demo is unavailable, and not which of those
            # it was: one of them is a fact about the server's inventory.
            log.warning("pipeline_unavailable reason=%s", exc)
            return JSONResponse(UNAVAILABLE_BODY, status_code=503)

        # The transport's answer: an SDP, its type, and a `pc_id` naming the peer
        # connection. No room key, no provider name, no session identifier — the
        # browser leaves this exchange knowing how to reach a media socket and
        # nothing about what is on the other end.
        #
        # `pc_id` is inert here and worth saying why, because it looks like a
        # handle. This endpoint creates a new connection for every offer and
        # never looks one up by id, so holding a `pc_id` reaches nothing: a
        # second offer is a second room token check, whoever sends it.
        displaced = offers.register(room, connection)
        if displaced is not None:
            # A room token authorises one browser to join one room. The common
            # way a second offer arrives is a reconnect, not an attack, so the
            # older call is ended rather than the newer one refused — C-23 stays
            # true and one token still holds one call open, not many.
            log.info("call_replaced room=%s", room[:32])
            await displaced.disconnect()

        return JSONResponse(answer)

    async def healthz(_request):
        return JSONResponse({"status": "ok"})

    def _forward(method: str, path: str, body: bytes, peer: str):
        """One request, forwarded as-is, with the caller's address attached.

        The address is **overwritten**, never appended to. A browser can put
        whatever it likes in `X-Forwarded-For`, and the application reads that
        header to decide whose budget to charge; trusting the incoming value
        would hand every caller the ability to pick their own rate-limit key,
        which is the same failure `client_ip` exists to avoid. What this process
        knows for a fact is the peer address of the socket, so that is the only
        thing it says.

        Nothing else is carried across: no cookies, no authorization header, no
        client-chosen hop headers. The API sees a request with a content type, a
        body, and one address this process vouches for.
        """
        headers = {"content-type": "application/json", "x-forwarded-for": peer}
        return upstream.request(method, path, content=body or None, headers=headers)

    def _passthrough(method: str, path: str):
        async def handler(request):
            body = await request.body()
            if len(body) > MAX_BODY_BYTES:
                return JSONResponse(UNAVAILABLE_BODY, status_code=503)

            peer = request.client.host if request.client else ""
            try:
                response = await run_in_threadpool(_forward, method, path, body, peer)
            except httpx.HTTPError as exc:
                # C-30. The page has words for this: "Couldn't reach the booking
                # system. Nothing has been changed."
                log.warning(
                    "passthrough_unreachable path=%s error=%s",
                    path,
                    exc.__class__.__name__,
                )
                return JSONResponse(UNAVAILABLE_BODY, status_code=503)

            # The application's own answer, verbatim — including its uniform 429,
            # which the page turns into "the demo is busy". Only the content type
            # is carried back; this process adds no header of its own beyond the
            # instruction not to cache a minted token.
            return Response(
                content=response.content,
                status_code=response.status_code,
                media_type=response.headers.get("content-type", "application/json"),
                headers={"cache-control": "no-store"},
            )

        return handler

    routes = [
        Route("/", page, methods=["GET"]),
        Route(OFFER_PATH, offer, methods=["POST"]),
        Route("/healthz", healthz, methods=["GET"]),
    ]
    # Built from the list, so the routing table and the allowlist cannot drift
    # apart. Anything not named there does not exist on this server.
    routes += [
        Route(path, _passthrough(method, path), methods=[method])
        for method, path in BROWSER_PASSTHROUGH
    ]

    return Starlette(routes=routes)


__all__ = [
    "BROWSER_PASSTHROUGH",
    "BUSY_BODY",
    "CONTENT_SECURITY_POLICY",
    "DEFAULT_API_URL",
    "MAX_BODY_BYTES",
    "OFFER_PATH",
    "PAGE_HEADERS",
    "PASSTHROUGH_TIMEOUT",
    "TRUSTED_PROXY_HOPS_VARIABLE",
    "WEB_SERVER_NEVER_LOAD",
    "create_app",
]
