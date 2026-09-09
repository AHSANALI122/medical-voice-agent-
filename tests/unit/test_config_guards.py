"""Non-negotiables that live in configuration."""

from __future__ import annotations

import base64
import secrets

import pytest
from pydantic import ValidationError

from app.config import Settings


def _keys() -> dict[str, str]:
    return {
        field: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        for field in (
            "vb_encryption_key",
            "vb_reference_hmac_key",
            "vb_channel_secret_web",
            "vb_channel_secret_phone",
            "vb_channel_secret_tester",
            "vb_room_token_key",
        )
    }


def test_demo_mode_refuses_to_start_in_production():
    with pytest.raises(ValidationError) as exc:
        Settings(env="production", demo_mode=True, _env_file=None, **_keys())
    assert "DEMO_MODE" in str(exc.value)


def test_production_refuses_to_start_without_keys(monkeypatch):
    # The test process has keys in its environment; production must be judged
    # against an environment that does not.
    for name in (
        "VB_ENCRYPTION_KEY",
        "VB_REFERENCE_HMAC_KEY",
        "VB_CHANNEL_SECRET_WEB",
        "VB_CHANNEL_SECRET_PHONE",
        "VB_CHANNEL_SECRET_TESTER",
        "VB_ROOM_TOKEN_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ValidationError) as exc:
        Settings(env="production", demo_mode=False, _env_file=None)
    assert "required when ENV=production" in str(exc.value)


def test_production_starts_with_every_key_present():
    settings = Settings(env="production", demo_mode=False, _env_file=None, **_keys())
    assert len(settings.encryption_key) == 32
    assert len(settings.reference_hmac_key) == 32
    # F12 — the browser's room-token key is required in production like every
    # other one. A generated-per-boot key would invalidate every token in flight
    # on a restart, which on a free tier is a routine event.
    assert len(settings.room_token_key) == 32


def test_development_generates_ephemeral_keys_rather_than_shipping_one(caplog):
    """No key is ever committed. A missing one is generated per boot, which is
    coherent with an ephemeral database: it protects exactly what survives a
    restart, which is nothing.
    """
    settings = Settings(env="development", demo_mode=True, _env_file=None)
    assert len(settings.encryption_key) == 32
    assert settings.channel_secret("web") != settings.channel_secret("phone")


def test_each_channel_has_its_own_secret():
    settings = Settings(env="development", demo_mode=True, _env_file=None, **_keys())
    secrets_seen = {
        settings.channel_secret(channel) for channel in ("web", "phone", "tester")
    }
    assert len(secrets_seen) == 3
    assert settings.channel_secret("admin") is None
