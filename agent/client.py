"""The agent's only way into the application (F12, F13 — C-19).

This file is the trust boundary. Everything the voice layer can make the system
do, it does through here, over HTTP, with the same signature any external caller
computes. There is no other door.

**The signing code is written out rather than imported**, exactly as it is in
`tester/client.py` and for the same reason. Importing `app.security.request_auth`
would make the agent agree with the server by construction, which is precisely
the agreement a third-party client does not get. Written out, the agent is a
real client of the published canonical form: if the server changes how it signs
and forgets to say so, the agent breaks the way Vapi would, in CI, rather than
in production.

Nothing in this package imports `app.services`, `app.db`, `app.models`,
`app.security` or `app.tools`. `scripts/check_import_boundary.py` fails the
build if that ever stops being true (C-19). It is worth being blunt about why:
an earlier draft of this design had a boundary that a single import could walk
through, which meant it had no boundary at all.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

HEADER_CHANNEL = "x-vb-channel"
HEADER_TIMESTAMP = "x-vb-timestamp"
HEADER_NONCE = "x-vb-nonce"
HEADER_SIGNATURE = "x-vb-signature"
HEADER_CALL_ID = "x-vb-call-id"
HEADER_CORRELATION = "x-correlation-id"

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_SECONDS = 8.0

# The complete surface the agent may call. Written as a closed set so a
# compromised model cannot reach a path this package never meant to expose:
# `call()` refuses an unknown tool before a request is built.
TOOLS: tuple[str, ...] = (
    "create_session",
    "resolve_date",
    "screen_turn",
    "search_doctors",
    "get_available_slots",
    "book_appointment",
    "append_reference_digits",
    "clear_reference_digits",
    "cancel_appointment",
)

# Never logged, never put in a transcript, never returned to the model twice.
# The reference is spoken once and then it belongs to the caller (5.1).
SENSITIVE_FIELDS = frozenset({"reference"})
MASK = "••••"


class MissingSecret(RuntimeError):
    pass


class UnknownTool(RuntimeError):
    """A tool name outside the published surface. Refused before a request."""


@dataclass(frozen=True)
class ToolResponse:
    tool: str
    status_code: int
    body: dict[str, Any]
    latency_ms: float
    correlation_id: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def reachable(self) -> bool:
        """False when the request never landed. C-30: an unreachable API is an
        ordinary outcome with defined behaviour, not a crash.
        """
        return self.status_code != 0

    def for_transcript(self) -> dict[str, Any]:
        """The body with anything that must not be written twice masked."""
        return {
            key: MASK if key in SENSITIVE_FIELDS else value
            for key, value in self.body.items()
        }


def channel_secret(channel: str, environ: dict[str, str] | None = None) -> bytes:
    """From the environment only. No secret is read from the repository (C-16).

    And no secret reaches a browser: the web channel's secret lives in the
    server-side Pipecat process, never in a page. `scripts/check_client_bundle.py`
    is what keeps that a fact rather than an intention.
    """
    source = environ if environ is not None else os.environ
    variable = f"VB_CHANNEL_SECRET_{channel.upper()}"
    raw = source.get(variable, "")
    if not raw:
        raise MissingSecret(
            f"{variable} is not set. The agent authenticates like every other "
            "external caller and cannot run without it."
        )
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def sign(secret: bytes, timestamp: str, nonce: str, raw_body: bytes, call_id: str = "") -> str:
    """The published canonical form: timestamp, nonce, call id, raw body."""
    message = b".".join(
        (
            timestamp.encode("ascii"),
            nonce.encode("ascii"),
            call_id.encode("ascii"),
            raw_body,
        )
    )
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


@dataclass
class ToolClient:
    """One conversation's worth of tool calls.

    `call_id` is the platform's identifier for the call — Vapi's on the phone,
    the room id on the web. It is signed, because it is a rate-limit key and an
    unsigned one is a key the caller picks (F8, C-34).

    `session_id` is held here purely so the pipeline does not have to thread it
    through every call site. It is not a credential and holding it grants
    nothing: authority is a reference match performed server-side, per request
    (C-38).
    """

    channel: str = "web"
    base_url: str = DEFAULT_BASE_URL
    call_id: str | None = None
    secret: bytes | None = None
    http: httpx.Client | None = None
    session_id: str | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    history: list[ToolResponse] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.secret is None:
            self.secret = channel_secret(self.channel)
        if self.http is None:
            self.http = httpx.Client(
                base_url=self.base_url, timeout=self.timeout_seconds
            )

    # ---------------------------------------------------------------- calls

    def call(self, tool: str, **arguments: Any) -> ToolResponse:
        if tool not in TOOLS:
            raise UnknownTool(tool)

        body = json.dumps(arguments).encode()
        timestamp = str(int(time.time()))
        # A fresh nonce per attempt, including per retry. A retry has to be a new
        # request or the server's replay window cannot tell it from a capture;
        # idempotency is what makes the retry safe, not nonce reuse (F15).
        nonce = secrets.token_hex(16)
        call_id = self.call_id or ""

        headers = {
            "content-type": "application/json",
            HEADER_CHANNEL: self.channel,
            HEADER_TIMESTAMP: timestamp,
            HEADER_NONCE: nonce,
            HEADER_SIGNATURE: sign(self.secret, timestamp, nonce, body, call_id),
        }
        if call_id:
            headers[HEADER_CALL_ID] = call_id

        started = time.perf_counter()
        try:
            response = self.http.post(f"/tools/{tool}", content=body, headers=headers)
        except httpx.HTTPError as exc:
            # C-30. Status 0 means the request never landed. The pipeline has a
            # defined utterance for this; it does not crash and it does not
            # invent a confirmation.
            record = ToolResponse(
                tool=tool,
                status_code=0,
                body={"detail": f"tool api unreachable: {exc.__class__.__name__}"},
                latency_ms=(time.perf_counter() - started) * 1000,
            )
            self.history.append(record)
            return record

        latency_ms = (time.perf_counter() - started) * 1000
        try:
            payload = response.json()
        except ValueError:
            payload = {"detail": response.text}
        if not isinstance(payload, dict):
            payload = {"body": payload}

        record = ToolResponse(
            tool=tool,
            status_code=response.status_code,
            body=payload,
            latency_ms=latency_ms,
            correlation_id=response.headers.get(HEADER_CORRELATION),
        )
        self.history.append(record)
        return record

    # ------------------------------------------------------------- helpers

    def open_session(self, *, consent_given: bool) -> ToolResponse:
        """Consent is a fact the browser establishes before the microphone is
        live (C-27), and it is passed through rather than assumed here.
        """
        response = self.call("create_session", consent_given=consent_given)
        if response.ok:
            self.session_id = response.body.get("session_id")
        return response

    def screen(self, utterance: str) -> ToolResponse:
        """The F10 pre-filter. Called first, every turn, before anything else.

        The agent does not decide whether to call this and does not get a vote
        on the result: `agent.turn` runs it unconditionally and obeys the
        answer. A guardrail the model chooses to invoke is a guardrail an
        injected utterance can talk it out of.
        """
        return self.call("screen_turn", session_id=self.session_id, utterance=utterance)

    def close(self) -> None:
        if self.http is not None:
            self.http.close()
