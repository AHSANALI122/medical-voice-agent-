"""Source-address resolution (C-34).

A rate limit whose key the attacker picks is not a rate limit. X-Forwarded-For
is a header, which means it is a client-supplied string, which means it is only
believable as far back as the proxies you actually run.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.config import get_settings
from app.security.request_auth import UNKNOWN_IP, client_ip


@dataclass
class FakeClient:
    host: str


@dataclass
class FakeRequest:
    headers: dict
    client: FakeClient | None


@pytest.fixture
def hops():
    settings = get_settings()
    original = settings.vb_trusted_proxy_hops

    def _set(value: int) -> None:
        object.__setattr__(settings, "vb_trusted_proxy_hops", value)

    yield _set
    _set(original)


def test_with_no_proxy_the_peer_address_is_the_client(hops):
    hops(0)
    request = FakeRequest(headers={}, client=FakeClient("203.0.113.9"))
    assert client_ip(request) == "203.0.113.9"


def test_with_no_proxy_a_forwarded_header_is_ignored(hops):
    """The attack: send X-Forwarded-For yourself and get a fresh budget per
    request. Not trusting the header by default is what stops it.
    """
    hops(0)
    request = FakeRequest(
        headers={"x-forwarded-for": "1.2.3.4"}, client=FakeClient("203.0.113.9")
    )
    assert client_ip(request) == "203.0.113.9"


def test_with_one_proxy_the_last_forwarded_entry_wins(hops):
    """Proxies append. With one in front, the entry it appended is the peer it
    saw, and everything to the left of that is whatever the client typed.
    """
    hops(1)
    request = FakeRequest(
        headers={"x-forwarded-for": "9.9.9.9, 203.0.113.9"},
        client=FakeClient("10.0.0.1"),
    )
    assert client_ip(request) == "203.0.113.9"


def test_a_spoofed_prefix_cannot_shift_the_key(hops):
    hops(1)
    spoofed = FakeRequest(
        headers={"x-forwarded-for": "evil-1, evil-2, evil-3, 203.0.113.9"},
        client=FakeClient("10.0.0.1"),
    )
    honest = FakeRequest(
        headers={"x-forwarded-for": "203.0.113.9"}, client=FakeClient("10.0.0.1")
    )
    assert client_ip(spoofed) == client_ip(honest) == "203.0.113.9"


def test_a_short_forwarded_chain_falls_back_to_the_peer(hops):
    hops(2)
    request = FakeRequest(
        headers={"x-forwarded-for": "203.0.113.9"}, client=FakeClient("10.0.0.1")
    )
    assert client_ip(request) == "10.0.0.1"


def test_a_missing_peer_is_named_rather_than_crashing(hops):
    hops(0)
    assert client_ip(FakeRequest(headers={}, client=None)) == UNKNOWN_IP
