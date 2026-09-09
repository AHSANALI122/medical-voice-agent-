"""The tester's HTTP client (F9, C-13).

The tester is not a backdoor and this file is where that is either true or not.
It holds the `tester` channel secret, signs exactly like any external caller, and
reaches the API over HTTP. There is no privileged path and no shortcut.

**The signing code is deliberately duplicated rather than imported.** Importing
`app.security.request_auth` would make the tester agree with the server by
construction, which is precisely the agreement a third-party client does not get.
Written out here, the tester is a real client of the published canonical form:
if the server changes how it signs and forgets to say so, the tester breaks the
way Vapi would. `tests/contract/test_f9_tester.py` is what keeps the two honest.

Nothing in this package imports `app.services`, `app.db`, `app.models`,
`app.security` or `app.tools`. `scripts/check_import_boundary.py` enforces it.
"""

from __future__ import annotations

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

DEFAULT_BASE_URL = "http://127.0.0.1:8000"

# Response fields that must never be written anywhere durable. The reference is
# spoken once and then it is the caller's to keep; the tester shows it once, in
# the confirmation panel, and masks it everywhere it would otherwise pile up.
REDACTED_FIELDS = frozenset({"reference"})
MASK = "••••"


class MissingSecret(RuntimeError):
    pass


@dataclass
class ToolCall:
    """One request, as the panel displays it."""

    tool: str
    arguments: dict[str, Any]
    status_code: int
    latency_ms: float
    response: dict[str, Any]

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def safe_response(self) -> dict[str, Any]:
        return redact(self.response)

    @property
    def safe_arguments(self) -> dict[str, Any]:
        return redact(self.arguments)


def redact(payload: Any) -> Any:
    """Mask the booking reference wherever it appears.

    The tester keeps a scrolling log of every call, which is a transcript by
    another name. A reference that survives in a transcript is a reference that
    outlives the moment it was disclosed in.
    """
    if isinstance(payload, dict):
        return {
            key: MASK if key in REDACTED_FIELDS else redact(value)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [redact(item) for item in payload]
    return payload


def channel_secret(channel: str = "tester", environ: dict[str, str] | None = None) -> bytes:
    """From the environment only. No secret is read from the repository."""
    source = environ if environ is not None else os.environ
    raw = source.get(f"VB_CHANNEL_SECRET_{channel.upper()}", "")
    if not raw:
        raise MissingSecret(
            f"VB_CHANNEL_SECRET_{channel.upper()} is not set. "
            "The tester authenticates like every other channel and cannot run without it."
        )
    import base64

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
    base_url: str = DEFAULT_BASE_URL
    channel: str = "tester"
    call_id: str | None = None
    secret: bytes | None = None
    http: httpx.Client | None = None
    history: list[ToolCall] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.secret is None:
            self.secret = channel_secret(self.channel)
        if self.http is None:
            self.http = httpx.Client(base_url=self.base_url, timeout=10.0)

    def call(self, tool: str, **arguments: Any) -> ToolCall:
        body = json.dumps(arguments).encode()
        timestamp = str(int(time.time()))
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
            # An unreachable API is an ordinary outcome, not a crash. C-30 says
            # provider failure must have defined behaviour, and a tester that
            # dies with a stack trace when the server is not running is a tester
            # that teaches nothing about the failure it is supposed to model.
            # Status 0 means "the request never landed".
            latency_ms = (time.perf_counter() - started) * 1000
            record = ToolCall(
                tool=tool,
                arguments=arguments,
                status_code=0,
                latency_ms=latency_ms,
                response={"detail": f"could not reach the API at {self.base_url}: {exc}"},
            )
            self.history.append(record)
            return record

        latency_ms = (time.perf_counter() - started) * 1000

        try:
            payload = response.json()
        except ValueError:
            payload = {"detail": response.text}

        record = ToolCall(
            tool=tool,
            arguments=arguments,
            status_code=response.status_code,
            latency_ms=latency_ms,
            response=payload if isinstance(payload, dict) else {"body": payload},
        )
        self.history.append(record)
        return record


# The complete tool surface, as the tester knows it. Kept here so a test can
# assert that it is exactly the API's own surface — no endpoint the tester can
# reach that the voice channels cannot (F9 acceptance), and none it has quietly
# stopped exercising either.
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
