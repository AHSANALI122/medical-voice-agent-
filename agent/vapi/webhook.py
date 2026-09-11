"""Translating a Vapi tool call into a signed request (F13 — C-03, C-04).

This is the phone channel's half of the network hop. Vapi posts a tool call
here; this module verifies that it really came from Vapi, converts it into
arguments the published API accepts, and signs it as the `phone` channel.

Three things it refuses to do, and each is the point of a finding:

**It never trusts the payload's own account of who is calling.** The post is
authenticated first, in constant time, against a secret that is not the channel
secret. Vapi proving it is Vapi and the agent proving it is a known channel are
two different claims and they use two different keys. `verify_signature` below
carries the detail — there are two schemes and they are checked separately.

**It never forwards a field the API did not ask for.** The tool arguments are
rebuilt from a whitelist per tool rather than passed through, so a model that
invents `appointment_id`, `patient_id` or `is_admin` produces a request that
simply does not contain it. Strict Pydantic on the far side would reject it
anyway (`extra="forbid"`); this is the same rule applied one hop earlier, where
it also stops the field reaching a log.

**It never lets the payload choose the session.** `session_id` comes from the
call's own state on this side, keyed by Vapi's call id. A model that supplies a
session id is supplying a value that is discarded.

Nothing here decides whether a caller may cancel anything. That decision is a
reference match, it happens server-side, and it happens on every request (5.2).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Any

from agent.client import ToolClient, ToolResponse

VAPI_SIGNATURE_HEADER = "x-vapi-signature"
VAPI_SECRET_HEADER = "x-vapi-secret"

# Both of these now live in `agent/toolcalls.py`, shared with the web channel.
# F13 asks for parity — the same conversation, the same database state on web
# and phone — and two copies of an argument allowlist is the most reliable way
# to lose that quietly. Re-exported here because this module's name for them is
# part of its published surface.
from agent.toolcalls import (  # noqa: E402
    ALLOWED_ARGUMENTS,
    NEEDS_IDEMPOTENCY_KEY,
)


class UnauthenticatedWebhook(Exception):
    """One exception for every rejection: bad signature, missing header, unknown
    tool, malformed body. The sender learns that it was refused and no more.
    """


class UnknownTool(UnauthenticatedWebhook):
    pass


def webhook_secret(environ: dict[str, str] | None = None) -> bytes:
    source = environ if environ is not None else os.environ
    raw = source.get("VB_VAPI_WEBHOOK_SECRET", "")
    if not raw:
        raise UnauthenticatedWebhook(
            "VB_VAPI_WEBHOOK_SECRET is not set; every webhook will be refused."
        )
    return raw.encode("utf-8")


def _constant_time_equals(left: bytes, right: bytes) -> bool:
    """Compare two secrets without leaking their length.

    `hmac.compare_digest` is constant-time across the *contents* it compares but
    returns early on a length mismatch, so comparing a configured secret against
    an attacker-chosen header would leak how long the secret is. Digesting both
    sides first makes every comparison the same 32 bytes.
    """
    return hmac.compare_digest(hashlib.sha256(left).digest(), hashlib.sha256(right).digest())


def verify_signature(raw_body: bytes, headers: dict[str, str], *, secret: bytes) -> None:
    """Prove the post came from Vapi. Two schemes, checked separately.

    Vapi sends one of two things depending on how the assistant's Server URL is
    configured, and they are **not** the same check:

      `X-Vapi-Signature`  HMAC-SHA256 of the raw body, hex.
      `X-Vapi-Secret`     the shared secret itself, literally.

    Treating them as one check — computing an HMAC and comparing it to whichever
    header turned up — is what this function used to do, and it meant every
    dashboard-configured `X-Vapi-Secret` post was refused with a 401 that looked
    like a misconfiguration on the sender's side.

    **A header that is present must validate under its own scheme.** There is no
    falling through from a failed signature to the shared secret: "try each
    scheme until one passes" turns two checks into a choice the caller makes,
    and the caller here is untrusted. The signature is preferred when both are
    present, because it is the stronger claim — it binds the body, so a tampered
    byte anywhere breaks it, including in a field this version does not read
    (the same reason the tool API signs raw bytes in F4).

    **Neither scheme is replay-proof, and that is stated rather than hidden.**
    Vapi sends no timestamp and no nonce, so a captured post replays under
    either scheme — unlike `/tools/*`, which has both (F4). What blunts it is
    downstream: a replayed `book_appointment` carries the same Vapi tool-call id,
    which maps to the same idempotency key, which the API answers as a replay
    rather than a second appointment (F15). A replayed `cancel_appointment` is
    idempotent for the same reason a repeated one is (F14). The residual is a
    process restart, which empties the tool-call map; the database's unique index
    on an active slot is what still holds there.
    """
    lowered = {key.lower(): value for key, value in headers.items()}
    signature = lowered.get(VAPI_SIGNATURE_HEADER)
    shared = lowered.get(VAPI_SECRET_HEADER)

    if signature is not None:
        expected = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
        if _constant_time_equals(expected.encode("ascii"), signature.strip().encode("utf-8")):
            return
        raise UnauthenticatedWebhook()

    if shared is not None:
        if _constant_time_equals(secret, shared.strip().encode("utf-8")):
            return
        raise UnauthenticatedWebhook()

    raise UnauthenticatedWebhook()


@dataclass(frozen=True)
class ToolCall:
    """One tool call, already stripped to what the API accepts."""

    id: str
    tool: str
    arguments: dict[str, Any]
    call_id: str | None


def _sanitize(tool: str, arguments: Any) -> dict[str, Any]:
    allowed = ALLOWED_ARGUMENTS.get(tool)
    if allowed is None:
        raise UnknownTool(tool)
    if isinstance(arguments, str):
        # Some model providers hand back the arguments as a JSON string.
        try:
            arguments = json.loads(arguments)
        except ValueError:
            raise UnauthenticatedWebhook() from None
    if not isinstance(arguments, dict):
        raise UnauthenticatedWebhook()
    return {key: value for key, value in arguments.items() if key in allowed}


def parse_tool_calls(payload: dict[str, Any]) -> list[ToolCall]:
    """Pull the tool calls out of a Vapi webhook body.

    Tolerant about the envelope, strict about the contents: providers move
    fields between versions, but no version of any provider gets to add an
    argument to a tool.
    """
    message = payload.get("message") or payload
    call_id = ((message.get("call") or {}).get("id")) or payload.get("callId")
    if isinstance(call_id, str):
        # It becomes a rate-limit key, so it is bounded and drawn from a closed
        # character set before anything is done with it (F8).
        call_id = "".join(c for c in call_id if c.isalnum() or c in "-_")[:64] or None
    else:
        call_id = None

    raw_calls = message.get("toolCalls") or message.get("toolCallList") or []
    parsed: list[ToolCall] = []
    for raw in raw_calls:
        if not isinstance(raw, dict):
            continue
        function = raw.get("function") or {}
        name = function.get("name") or raw.get("name")
        if not isinstance(name, str):
            raise UnknownTool("unnamed")
        parsed.append(
            ToolCall(
                id=str(raw.get("id") or ""),
                tool=name,
                arguments=_sanitize(name, function.get("arguments") or {}),
                call_id=call_id,
            )
        )
    return parsed


@dataclass
class CallState:
    """What this side remembers about one platform call.

    A session id and nothing else. No patient, no tier, no standing authority —
    the same posture as the server-side session record it names (C-38).
    """

    session_id: str | None = None
    idempotency_keys: dict[str, str] = field(default_factory=dict)

    def idempotency_key_for(self, tool_call_id: str) -> str:
        """One key per tool call id, minted here and remembered.

        Vapi retries a tool call with the same id after a timeout, so keying on
        it is what turns a platform retry into an idempotent replay rather than
        a second appointment (F15).
        """
        import uuid

        if tool_call_id not in self.idempotency_keys:
            self.idempotency_keys[tool_call_id] = str(uuid.uuid4())
        return self.idempotency_keys[tool_call_id]


class VapiBridge:
    """Holds one call's state and forwards its tool calls to the API."""

    def __init__(self, *, base_url: str, secret: bytes | None = None) -> None:
        self.base_url = base_url
        self._secret = secret
        self._calls: dict[str, CallState] = {}
        self._clients: dict[str, ToolClient] = {}

    def state_for(self, call_id: str) -> CallState:
        return self._calls.setdefault(call_id, CallState())

    def client_for(self, call_id: str) -> ToolClient:
        if call_id not in self._clients:
            self._clients[call_id] = ToolClient(
                channel="phone", base_url=self.base_url, call_id=call_id
            )
        return self._clients[call_id]

    def handle(
        self, raw_body: bytes, headers: dict[str, str], *, consent_given: bool = True
    ) -> list[dict[str, Any]]:
        """Verify, translate, forward, and return Vapi's result envelopes.

        `consent_given` is True for the phone channel because the disclosure is
        the assistant's first spoken message and the caller stays on the line
        after hearing it (C-15). There is no UI gate to put it behind, which is
        exactly why C-27 asks for one on the web and not here.
        """
        verify_signature(raw_body, headers, secret=self._secret or webhook_secret())

        try:
            payload = json.loads(raw_body)
        except ValueError:
            raise UnauthenticatedWebhook() from None
        if not isinstance(payload, dict):
            raise UnauthenticatedWebhook()

        results: list[dict[str, Any]] = []
        for tool_call in parse_tool_calls(payload):
            if not tool_call.call_id:
                raise UnauthenticatedWebhook()
            response = self._forward(tool_call, consent_given=consent_given)
            results.append(
                {
                    "toolCallId": tool_call.id,
                    # `for_transcript` masks the reference. Vapi keeps its own
                    # transcript on its own servers, and a reference that lands
                    # there has outlived the moment it was disclosed in (5.1).
                    # The model still receives it in the same turn via the
                    # spoken confirmation the server composed.
                    "result": response.for_transcript(),
                }
            )
        return results

    def _forward(self, tool_call: ToolCall, *, consent_given: bool) -> ToolResponse:
        state = self.state_for(tool_call.call_id)
        client = self.client_for(tool_call.call_id)

        if state.session_id is None:
            opened = client.open_session(consent_given=consent_given)
            if not opened.ok:
                return opened
            state.session_id = client.session_id
        client.session_id = state.session_id

        arguments = dict(tool_call.arguments)
        # The session is this side's to supply. A payload that carried one had
        # it dropped by `_sanitize` already; this is where the real one arrives.
        arguments["session_id"] = state.session_id
        if tool_call.tool in NEEDS_IDEMPOTENCY_KEY:
            arguments["idempotency_key"] = state.idempotency_key_for(tool_call.id)

        return client.call(tool_call.tool, **arguments)


__all__ = [
    "ALLOWED_ARGUMENTS",
    "NEEDS_IDEMPOTENCY_KEY",
    "VAPI_SECRET_HEADER",
    "VAPI_SIGNATURE_HEADER",
    "CallState",
    "ToolCall",
    "UnauthenticatedWebhook",
    "UnknownTool",
    "VapiBridge",
    "parse_tool_calls",
    "verify_signature",
    "webhook_secret",
]
