"""Configuration. Secrets come from the environment only — never from the repo.

In a non-production environment a missing key is generated in memory at boot with
a loud warning. That is coherent with F0: the database is ephemeral by decision,
so an ephemeral key protects exactly as much data as survives a restart (none).
Under ENV=production every key is mandatory and startup fails without it.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from functools import lru_cache
from zoneinfo import ZoneInfo

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("voicebook.config")

KEY_BYTES = 32
CHANNELS = ("web", "phone", "tester")


def _b64d(value: str, field: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError(f"{field} is not valid base64url") from exc
    if len(raw) != KEY_BYTES:
        raise ValueError(f"{field} must decode to {KEY_BYTES} bytes, got {len(raw)}")
    return raw


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="", extra="ignore", case_sensitive=False
    )

    env: str = Field(default="development")
    demo_mode: bool = Field(default=True)

    vb_encryption_key: str = ""
    vb_encryption_key_id: str = "k1"
    vb_reference_hmac_key: str = ""

    vb_channel_secret_web: str = ""
    vb_channel_secret_phone: str = ""
    vb_channel_secret_tester: str = ""

    # F12 — the key the browser's room token is signed with. Distinct from every
    # channel secret because it protects a different thing and lives a different
    # length of time: a channel secret authenticates a server-side process, this
    # one authorizes one browser to join one room for one minute.
    vb_room_token_key: str = ""

    # F13 — the secret Vapi signs its webhooks with. Nothing in this repository
    # signs with it; the agent only ever verifies. It is separate from
    # VB_CHANNEL_SECRET_PHONE on purpose: one is Vapi proving it is Vapi to the
    # agent, the other is the agent proving it is a known channel to the API.
    vb_vapi_webhook_secret: str = ""

    vb_database_path: str = "data/voicebook.db"
    vb_clinic_timezone: str = "Asia/Karachi"

    # F10 — where an emergency is routed. Configurable because the right number
    # is a deployment fact, not a code fact.
    vb_emergency_service_name: str = "Rescue 1122"
    vb_emergency_number: str = "1122"

    # F1 / C-29 — schedule enumeration limits.
    max_slots_returned: int = 5
    slot_horizon_days: int = 14
    booking_lead_time_minutes: int = 120

    # F5 / C-34 — brute-force lockout, keyed on the caller (source IP plus the
    # name they are asking about), never on the appointment. Locking the record
    # would let anyone who knows a name and a date deny a real patient their own
    # booking; locking the caller costs the attacker and nobody else.
    max_reference_attempts: int = 5
    reference_lock_minutes: int = 60

    # F8 / C-07, C-14 — abuse budgets. Every one of these is configuration, and
    # every one is persisted, so a reconnect resets nothing (C-23).
    abuse_window_hours: int = 24
    # "A 4th call from one source inside 24h is refused" (F8 acceptance).
    max_sessions_per_ip_per_day: int = 3
    max_sessions_per_call_id_per_day: int = 3
    # Soft layer: a name is neither secret nor verified, so this is friction and
    # not a control. An abuser evades it by saying a different name.
    max_bookings_per_name_per_day: int = 3
    # Hard backstop: nothing the caller controls can move this one.
    max_bookings_per_day_global: int = 200

    # How many proxies sit in front of this service. 0 means the peer address is
    # the client. Any other value reads that many hops back from the right of
    # X-Forwarded-For, because everything to the left of your own proxy's entry
    # is attacker-supplied text.
    vb_trusted_proxy_hops: int = 0

    # F4 — request signature freshness window.
    signature_max_age_seconds: int = 300

    session_ttl_minutes: int = 15

    # F12 — a room token is good for one minute. Short because it is minted for
    # an unauthenticated browser: the browser holds no channel secret, so the
    # token's own lifetime is the whole of its containment.
    room_token_ttl_seconds: int = 60
    # F12 / C-18 — state-dependent VAD silence thresholds. They live here rather
    # than in `agent/` because the browser has to be told them and `app/` must
    # never import `agent/`; the *policy* that maps a state to one of them is
    # `agent.vad`, where the pipeline that applies it lives.
    vad_default_silence_ms: int = 700
    vad_digit_silence_ms: int = 1200
    # A separate budget from the call budget, so a legitimate mint-then-connect
    # does not spend two of the caller's three daily calls. Headroom for a
    # reconnect or two, and no more.
    max_room_tokens_per_ip_per_day: int = 6

    # F13 — the server half of the duration cap. Vapi enforces its own at the
    # platform; this one exists because a cap that only the platform enforces is
    # a cap the platform can be misconfigured out of. Ten minutes is far longer
    # than any booking conversation and far shorter than a toll-fraud call.
    max_call_seconds: int = 600

    @field_validator("env")
    @classmethod
    def _normalize_env(cls, v: str) -> str:
        return v.strip().lower()

    @model_validator(mode="after")
    def _guard_and_fill(self) -> "Settings":
        production = self.env == "production"

        # Non-negotiable: DEMO_MODE refuses to start in production.
        if production and self.demo_mode:
            raise ValueError("DEMO_MODE must be false when ENV=production")

        required = {
            "VB_ENCRYPTION_KEY": "vb_encryption_key",
            "VB_REFERENCE_HMAC_KEY": "vb_reference_hmac_key",
            "VB_CHANNEL_SECRET_WEB": "vb_channel_secret_web",
            "VB_CHANNEL_SECRET_PHONE": "vb_channel_secret_phone",
            "VB_CHANNEL_SECRET_TESTER": "vb_channel_secret_tester",
            "VB_ROOM_TOKEN_KEY": "vb_room_token_key",
        }
        for env_name, attr in required.items():
            if getattr(self, attr):
                continue
            if production:
                raise ValueError(f"{env_name} is required when ENV=production")
            generated = base64.urlsafe_b64encode(secrets.token_bytes(KEY_BYTES)).decode()
            object.__setattr__(self, attr, generated)
            log.warning(
                "%s not set; generated an ephemeral key for ENV=%s. "
                "References and encrypted rows will not survive a restart.",
                env_name,
                self.env,
            )
        return self

    @property
    def encryption_key(self) -> bytes:
        return _b64d(self.vb_encryption_key, "VB_ENCRYPTION_KEY")

    @property
    def reference_hmac_key(self) -> bytes:
        return _b64d(self.vb_reference_hmac_key, "VB_REFERENCE_HMAC_KEY")

    @property
    def room_token_key(self) -> bytes:
        return _b64d(self.vb_room_token_key, "VB_ROOM_TOKEN_KEY")

    @property
    def clinic_tz(self) -> ZoneInfo:
        return ZoneInfo(self.vb_clinic_timezone)

    def channel_secret(self, channel: str) -> bytes | None:
        """Per-channel shared secret (F4). Unknown channel returns None."""
        if channel not in CHANNELS:
            return None
        return _b64d(getattr(self, f"vb_channel_secret_{channel}"), f"channel:{channel}")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Test-only: re-read the environment."""
    get_settings.cache_clear()


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
