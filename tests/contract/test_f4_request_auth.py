"""F4 — request authentication (C-03, C-19)."""

from __future__ import annotations

import json
import time
import uuid

from app.config import get_settings
from app.security.request_auth import ReplayCache, sign


def _nonce() -> str:
    return uuid.uuid4().hex


def _headers(channel: str, timestamp: str, nonce: str, signature: str) -> dict:
    return {
        "content-type": "application/json",
        "x-vb-channel": channel,
        "x-vb-timestamp": timestamp,
        "x-vb-nonce": nonce,
        "x-vb-signature": signature,
    }


BODY = json.dumps({"consent_given": True}).encode()


def test_a_correctly_signed_request_is_accepted(api):
    assert api.post("/tools/create_session", {"consent_given": True}).status_code == 200


def test_an_unsigned_request_is_rejected(client):
    response = client.post("/tools/create_session", json={"consent_given": True})
    assert response.status_code == 401


def test_a_tampered_body_is_rejected(api):
    timestamp = str(int(time.time()))
    nonce = _nonce()
    signature = sign(get_settings().channel_secret("web"), timestamp, nonce, BODY)

    tampered = json.dumps({"consent_given": False}).encode()
    response = api.raw_post(
        "/tools/create_session", tampered, _headers("web", timestamp, nonce, signature)
    )
    assert response.status_code == 401


def test_a_stale_timestamp_is_rejected(api):
    settings = get_settings()
    stale = str(int(time.time()) - settings.signature_max_age_seconds - 60)
    nonce = _nonce()
    signature = sign(settings.channel_secret("web"), stale, nonce, BODY)
    response = api.raw_post(
        "/tools/create_session", BODY, _headers("web", stale, nonce, signature)
    )
    assert response.status_code == 401


def test_a_replayed_request_is_rejected(api):
    timestamp = str(int(time.time()))
    nonce = _nonce()
    signature = sign(get_settings().channel_secret("web"), timestamp, nonce, BODY)
    headers = _headers("web", timestamp, nonce, signature)

    assert api.raw_post("/tools/create_session", BODY, headers).status_code == 200
    assert api.raw_post("/tools/create_session", BODY, headers).status_code == 401


def test_an_honest_retry_of_the_same_payload_is_not_a_replay(api):
    """Replay protection must not punish a client whose first attempt timed out.

    Same bytes, same second, fresh nonce: that is a retry, and F15 decides what
    it means. Only a reused nonce is a replay. Without this the two controls
    fight, and the one that loses is the client sitting on a flaky phone line.
    """
    timestamp = str(int(time.time()))
    secret = get_settings().channel_secret("web")

    for _ in range(2):
        nonce = _nonce()
        signature = sign(secret, timestamp, nonce, BODY)
        response = api.raw_post(
            "/tools/create_session", BODY, _headers("web", timestamp, nonce, signature)
        )
        assert response.status_code == 200


def test_a_missing_nonce_is_rejected(api):
    timestamp = str(int(time.time()))
    nonce = _nonce()
    signature = sign(get_settings().channel_secret("web"), timestamp, nonce, BODY)
    headers = _headers("web", timestamp, nonce, signature)
    del headers["x-vb-nonce"]
    assert api.raw_post("/tools/create_session", BODY, headers).status_code == 401


def test_a_failed_signature_does_not_burn_the_nonce(api):
    """Otherwise anyone who can observe a nonce can deny its owner the request."""
    timestamp = str(int(time.time()))
    nonce = _nonce()

    bad = api.raw_post(
        "/tools/create_session", BODY, _headers("web", timestamp, nonce, "deadbeef")
    )
    assert bad.status_code == 401

    signature = sign(get_settings().channel_secret("web"), timestamp, nonce, BODY)
    good = api.raw_post(
        "/tools/create_session", BODY, _headers("web", timestamp, nonce, signature)
    )
    assert good.status_code == 200


def test_a_signature_from_another_channels_secret_is_rejected(api):
    """Separate secret per channel: a leaked tester key does not open the phone."""
    timestamp = str(int(time.time()))
    nonce = _nonce()
    signature = sign(get_settings().channel_secret("tester"), timestamp, nonce, BODY)
    response = api.raw_post(
        "/tools/create_session", BODY, _headers("phone", timestamp, nonce, signature)
    )
    assert response.status_code == 401


def test_an_unknown_channel_is_rejected(api):
    timestamp = str(int(time.time()))
    nonce = _nonce()
    signature = sign(get_settings().channel_secret("web"), timestamp, nonce, BODY)
    response = api.raw_post(
        "/tools/create_session", BODY, _headers("admin", timestamp, nonce, signature)
    )
    assert response.status_code == 401


def test_every_authentication_failure_says_the_same_thing(api):
    timestamp = str(int(time.time()))
    nonce = _nonce()
    good = sign(get_settings().channel_secret("web"), timestamp, nonce, BODY)

    responses = [
        api.raw_post(
            "/tools/create_session", BODY, _headers("web", timestamp, _nonce(), "deadbeef")
        ),
        api.raw_post("/tools/create_session", BODY, _headers("admin", timestamp, nonce, good)),
        api.raw_post("/tools/create_session", BODY, _headers("web", "0", nonce, good)),
    ]
    assert {r.status_code for r in responses} == {401}
    assert len({r.json()["detail"] for r in responses}) == 1


def test_replay_cache_forgets_entries_older_than_the_window():
    cache = ReplayCache(window_seconds=300)
    assert cache.seen_before("nonce", now=1000.0) is False
    assert cache.seen_before("nonce", now=1000.0) is True
    # Past the window the entry is gone, and the timestamp check is what stops
    # the replay from that point on.
    assert cache.seen_before("nonce", now=2000.0) is False
