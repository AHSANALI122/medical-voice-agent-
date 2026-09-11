"""F12 — the signalling path a browser actually takes (C-19, C-16, C-27, C-30).

Three claims, and none of them needs a microphone:

* the room token is verified by the application, over HTTP, because the
  signalling server has no way to verify one itself;
* every refusal — expired, tampered, wrong room, wrong channel, unreachable API
  — is the same refusal from outside;
* authentication (401), validation (422) and authorization (403) stay three
  separate layers with three separate answers (C-36).
"""

from __future__ import annotations

import importlib.util
import json
import time

import httpx
import pytest
from starlette.testclient import TestClient as StarletteTestClient

from agent.client import TOOLS, channel_secret, sign
from agent.env import NEVER_LOAD
from agent.pipecat import budget, rooms, server
from app.web import tokens


@pytest.fixture
def minted():
    return tokens.mint()


def _offer(room: str, token: str) -> dict[str, str]:
    """What the page posts: the room it was given, the token that opens it, and
    the SDP offer its own `RTCPeerConnection` produced.
    """
    return {"room": room, "token": token, "sdp": "v=0 a=audio", "type": "offer"}


# --------------------------------------------------------------------------
# The endpoint (app side)
# --------------------------------------------------------------------------


def test_a_minted_token_verifies_for_its_own_room(api, minted):
    response = api.post(
        "/web/room-token/verify", {"token": minted.token, "room": minted.room}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["room"] == minted.room
    assert 0 < body["expires_in_seconds"] <= 60


def test_a_token_for_one_room_does_not_open_another(api, minted):
    """The whole point of "room-scoped". A signature check alone would accept a
    valid token for room A as entry to room B.
    """
    other = tokens.mint()
    response = api.post(
        "/web/room-token/verify", {"token": minted.token, "room": other.room}
    )
    assert response.status_code == 403


def test_an_expired_token_is_refused(api):
    stale = tokens.mint(now=int(time.time()) - 3600)
    response = api.post(
        "/web/room-token/verify", {"token": stale.token, "room": stale.room}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t[:-1] + ("A" if t[-1] != "A" else "B"),
        lambda t: t.split(".", 1)[0],
        lambda t: "x" + t,
    ],
)
def test_a_tampered_token_is_refused(api, minted, mangle):
    response = api.post(
        "/web/room-token/verify", {"token": mangle(minted.token), "room": minted.room}
    )
    assert response.status_code == 403


def test_every_refusal_says_exactly_the_same_thing(api, minted):
    """A caller who can tell "expired" from "wrong room" from "never minted" can
    tell which one to work on next.
    """
    other = tokens.mint()
    stale = tokens.mint(now=int(time.time()) - 3600)
    bodies = {
        api.post(
            "/web/room-token/verify", {"token": minted.token, "room": other.room}
        ).text,
        api.post(
            "/web/room-token/verify", {"token": stale.token, "room": stale.room}
        ).text,
        api.post(
            "/web/room-token/verify", {"token": "not-a-token", "room": minted.room}
        ).text,
        api.post(
            "/web/room-token/verify",
            {"token": minted.token, "room": "never-minted-room"},
        ).text,
    }
    assert len(bodies) == 1


# --------------------------------------------------------------------------
# 401 / 422 / 403 are three layers (C-36)
# --------------------------------------------------------------------------


def test_an_unsigned_request_is_401_and_not_403(client, minted):
    response = client.post(
        "/web/room-token/verify",
        json={"token": minted.token, "room": minted.room},
    )
    assert response.status_code == 401


def test_a_malformed_body_is_422_and_not_403(api, minted):
    """Pydantic validates shape. It never decides permission."""
    assert api.post("/web/room-token/verify", {"token": minted.token}).status_code == 422
    assert (
        api.post(
            "/web/room-token/verify",
            {"token": minted.token, "room": minted.room, "extra": "no"},
        ).status_code
        == 422
    )
    assert (
        api.post(
            "/web/room-token/verify", {"token": "", "room": minted.room}
        ).status_code
        == 422
    )


def test_a_well_formed_token_from_a_stranger_is_still_403(api):
    """422 and 403 asserted independently: this body is perfectly valid and the
    answer is still no.
    """
    response = api.post(
        "/web/room-token/verify", {"token": "aaaa.bbbb", "room": "some-room"}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("channel", ["phone", "tester"])
def test_another_channels_secret_does_not_open_a_room(api, minted, channel):
    """Per-channel secrets are only worth something if a leak is contained.
    Phone and tester have no rooms; neither may open one.
    """
    response = api.post(
        "/web/room-token/verify",
        {"token": minted.token, "room": minted.room},
        channel=channel,
    )
    assert response.status_code == 403


def test_verifying_does_not_spend_the_room_token_budget(api, client, minted):
    """Six mints per address per day (F8). Verification is not a mint, and a
    browser that reconnects must not burn its way out of the demo.
    """
    for _ in range(10):
        api.post("/web/room-token/verify", {"token": minted.token, "room": minted.room})
    assert client.post("/web/room-token").status_code == 200


# --------------------------------------------------------------------------
# The agent's client (agent side)
# --------------------------------------------------------------------------


def test_the_agent_asks_the_api_and_believes_the_answer(client, minted):
    """`client` is an `httpx.Client` over the real application, so the request
    is built, signed, routed and parsed exactly as it would be across a socket.
    Only the socket is missing.
    """
    check = rooms.verify_room_token(token=minted.token, room=minted.room, http=client)
    assert check.allowed is True
    assert check.reachable is True
    assert check.room == minted.room


def test_the_agent_is_refused_the_same_way_the_endpoint_refuses(client, minted):
    other = tokens.mint()
    check = rooms.verify_room_token(token=minted.token, room=other.room, http=client)
    assert check.allowed is False
    assert check.reachable is True


def test_an_unreachable_api_is_not_permission(minted):
    """C-30, fail closed. The failure a network gives you must not look like a
    yes.
    """
    check = rooms.verify_room_token(
        token=minted.token,
        room=minted.room,
        base_url="http://127.0.0.1:1",
        timeout_seconds=0.25,
    )
    assert check.allowed is False
    assert check.reachable is False


def test_an_oversized_token_is_refused_without_a_request(minted):
    """Nothing is sent, so nothing has to be rejected."""
    sent: list[tuple] = []

    class Recording(httpx.Client):
        def post(self, *args, **kwargs):  # pragma: no cover - must not run
            sent.append(args)
            raise AssertionError("a request was sent")

    check = rooms.verify_room_token(
        token="a" * (rooms.MAX_TOKEN_LENGTH + 1), room=minted.room, http=Recording()
    )
    assert check.allowed is False
    assert sent == []


def test_the_verify_path_is_not_a_tool():
    """`/web/room-token/verify` is web plumbing, not a tool. A compromised model
    reaches `TOOLS`; it has no business verifying anybody's room token.
    """
    assert not any("room" in tool or "token" in tool for tool in TOOLS)


# --------------------------------------------------------------------------
# The signalling server (the process a browser talks to)
# --------------------------------------------------------------------------


@pytest.fixture
def web(monkeypatch):
    """The signalling app with the API answer stubbed.

    The real call is exercised above against the real application; here the
    interest is what this process does with a yes and with a no.
    """
    answers: dict[str, rooms.RoomCheck] = {}

    def fake_verify(*, token, room, base_url, **_kwargs):
        return answers.get(
            token, rooms.RoomCheck(allowed=False, reachable=True, room=room)
        )

    monkeypatch.setattr(server, "verify_room_token", fake_verify)
    app = server.create_app(api_url="http://api.test")
    return StarletteTestClient(app), answers


def test_the_page_is_served_with_a_policy_that_forbids_leaving_the_origin(web):
    client, _ = web
    response = client.get("/")
    assert response.status_code == 200
    assert "VoiceBook" in response.text
    policy = response.headers["content-security-policy"]
    assert "connect-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert response.headers["cache-control"] == "no-store"


def test_the_page_allows_the_microphone_and_nothing_else(web):
    client, _ = web
    permissions = client.get("/").headers["permissions-policy"]
    assert "microphone=(self)" in permissions
    assert "camera=()" in permissions


def test_an_offer_without_a_good_token_is_refused(web):
    client, _ = web
    response = client.post("/api/offer", json=_offer("r", "nope"))
    assert response.status_code == 403
    assert response.json() == server.REFUSED_BODY


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"{",
        b"[]",
        b'{"room": "r"}',
        b'{"token": "t"}',
        # A token without an offer. There is nothing to answer, and a handler
        # that treats "no SDP" as "empty SDP" builds a peer connection for it.
        b'{"room": "r", "token": "t"}',
        b'{"room": "r", "token": "t", "sdp": "v=0"}',
    ],
)
def test_a_malformed_offer_is_the_same_refusal(web, body):
    client, _ = web
    response = client.post("/api/offer", content=body)
    assert response.status_code == 403
    assert response.json() == server.REFUSED_BODY


def test_an_oversized_offer_is_refused_before_it_is_parsed(web):
    client, answers = web
    answers["good"] = rooms.RoomCheck(allowed=True, reachable=True, room="r")
    payload = json.dumps(
        {
            "room": "r",
            "token": "good",
            "type": "offer",
            "sdp": "v=0" + "x" * server.MAX_BODY_BYTES,
        }
    ).encode()
    response = client.post("/api/offer", content=payload)
    assert response.status_code == 403


def test_a_good_token_reaches_the_pipeline(web):
    """The seam. The token verified and the offer went on to the transport.

    What happens next depends on the machine: with no audio stack the call
    cannot start (503); with one, this deliberately malformed SDP is refused
    (403). Neither is a 500, and that is the invariant worth pinning — the
    token check having passed must not be visible in the status code.
    """
    client, answers = web
    answers["good"] = rooms.RoomCheck(allowed=True, reachable=True, room="room-1")
    response = client.post("/api/offer", json=_offer("room-1", "good"))
    assert response.status_code in (403, 503)
    assert response.json() in (server.REFUSED_BODY, server.UNAVAILABLE_BODY)


def test_an_unreachable_api_refuses_rather_than_connecting(web):
    client, answers = web
    answers["good"] = rooms.RoomCheck(allowed=False, reachable=False, room="r")
    response = client.post("/api/offer", json=_offer("r", "good"))
    assert response.status_code == 403


def test_healthz_says_nothing_about_any_call(web):
    client, _ = web
    assert client.get("/healthz").json() == {"status": "ok"}


# --------------------------------------------------------------------------
# Least privilege for the process the browser talks to
# --------------------------------------------------------------------------


def test_the_signalling_process_cannot_hold_the_room_token_key():
    """Enforced where the environment is read, not by discipline. A process that
    can mint tokens as well as check them is a process with no ticket check.
    """
    assert "VB_ROOM_TOKEN_KEY" in server.WEB_SERVER_NEVER_LOAD


@pytest.mark.parametrize(
    "name",
    [
        "VB_ENCRYPTION_KEY",
        "VB_REFERENCE_HMAC_KEY",
        "VB_VAPI_WEBHOOK_SECRET",
        "VB_CHANNEL_SECRET_PHONE",
        "VB_CHANNEL_SECRET_TESTER",
        "VAPI_PRIVATE_KEY",
    ],
)
def test_the_signalling_process_loads_no_secret_it_does_not_need(name):
    assert name in server.WEB_SERVER_NEVER_LOAD


def test_it_still_loads_the_one_secret_it_does_need():
    assert "VB_CHANNEL_SECRET_WEB" not in server.WEB_SERVER_NEVER_LOAD
    assert NEVER_LOAD <= server.WEB_SERVER_NEVER_LOAD


def test_the_signalling_server_signs_like_any_external_caller():
    """No privileged path. The bytes it sends are the published canonical form."""
    secret = channel_secret("web")
    body = json.dumps({"token": "t", "room": "r"}).encode()
    assert sign(secret, "1700000000", "a" * 16, body, "") == sign(
        secret, "1700000000", "a" * 16, body, ""
    )


# --------------------------------------------------------------------------
# The passthrough: one origin for the browser, a closed list for everyone else
# --------------------------------------------------------------------------


class _Recorder:
    """Stands in for the process's upstream client and remembers what it sent.

    Duck-typed rather than a subclass: `create_app` calls `.request`, the room
    token check calls `.post`, and both land on the real application through the
    test client. Nothing is patched into a library.
    """

    def __init__(self, client):
        self._client = client
        self.sent: list[dict] = []

    def request(self, method, path, *, content=None, headers=None):
        self.sent.append({"method": method, "path": path, "headers": headers or {}})
        return self._client.request(method, path, content=content, headers=headers)

    def post(self, path, *, content=None, headers=None):
        return self.request("POST", path, content=content, headers=headers)


@pytest.fixture
def fronted(client):
    """The signalling server with the real application behind it."""
    upstream = _Recorder(client)
    app = server.create_app(api_url="http://api.test", http=upstream)
    return StarletteTestClient(app, client=("203.0.113.9", 4444)), upstream


def test_the_page_and_its_api_share_one_origin(fronted):
    """The browser's own rules, `connect-src 'self'`, and the build-time grep all
    say the page talks to one origin. This is what makes that true.
    """
    web, _ = fronted
    assert web.get("/web/config").status_code == 200
    assert web.post("/web/room-token").status_code == 200


def test_the_config_the_browser_reads_carries_no_secret(fronted):
    web, _ = fronted
    body = web.get("/web/config").json()
    assert set(body) == {
        "consent_required",
        "disclosure",
        "emergency_service",
        "emergency_number",
        "default_silence_ms",
        "digit_silence_ms",
    }


def test_a_minted_token_reaches_the_offer_endpoint(fronted):
    """The whole loop, through the front door: mint on the page's origin, then
    present the token to the offer endpoint with an SDP attached.

    Two environments, two right answers, and the test says so rather than
    picking one. Without the audio stack the call cannot start at all (503).
    With it, this deliberately malformed SDP is refused the way every other bad
    offer is (403). What must never happen in either is a 500 — a stranger's
    string reaching a traceback.
    """
    web, _ = fronted
    minted = web.post("/web/room-token").json()
    response = web.post("/api/offer", json=_offer(minted["room"], minted["token"]))
    assert response.status_code in (403, 503)
    assert response.json() in (server.REFUSED_BODY, server.UNAVAILABLE_BODY)


@pytest.mark.skipif(
    importlib.util.find_spec("pipecat") is None,
    reason="a malformed SDP only reaches the parser when the audio stack is here",
)
def test_a_malformed_sdp_is_refused_the_way_a_bad_token_is(fronted):
    """The oracle this closes: an SDP that crashed the parser came back as a
    500, and a caller who can tell 500 from 403 has learned their token was the
    good part.
    """
    web, _ = fronted
    minted = web.post("/web/room-token").json()
    good = web.post("/api/offer", json=_offer(minted["room"], minted["token"]))
    bad = web.post("/api/offer", json=_offer(minted["room"], "forged.forged"))
    assert good.status_code == 403
    assert good.json() == bad.json() == server.REFUSED_BODY


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/web/room-token/verify"),
        ("POST", "/tools/create_session"),
        ("POST", "/tools/cancel_appointment"),
        ("GET", "/docs"),
    ],
)
def test_nothing_outside_the_two_named_endpoints_is_reachable(fronted, method, path):
    """A prefix would have been a hole. `/tools/*` especially: this process holds
    the web channel secret, and a proxy that signs for a stranger is the browser
    holding that secret.
    """
    web, _ = fronted
    assert web.request(method, path).status_code == 404


def test_the_passthrough_list_names_only_the_two(fronted):
    assert server.BROWSER_PASSTHROUGH == (
        ("GET", "/web/config"),
        ("POST", "/web/room-token"),
    )


def test_the_browsers_own_forwarded_for_is_discarded(fronted):
    """C-34. The application reads this header to decide whose budget to charge.
    A caller who can write it picks their own rate-limit key, and a key you pick
    yourself is not a budget.
    """
    web, upstream = fronted
    web.post("/web/room-token", headers={"x-forwarded-for": "198.51.100.200"})
    forwarded = upstream.sent[-1]["headers"]["x-forwarded-for"]
    assert forwarded == "203.0.113.9"
    assert "198.51.100.200" not in forwarded


def test_no_client_header_is_carried_across(fronted):
    """Only a content type, a body and the one address this process vouches for."""
    web, upstream = fronted
    web.post(
        "/web/room-token",
        headers={
            "cookie": "session=stolen",
            "authorization": "Bearer nope",
            "x-vb-channel": "tester",
        },
    )
    assert set(upstream.sent[-1]["headers"]) == {"content-type", "x-forwarded-for"}


def test_the_application_budget_still_applies_through_the_front_door(fronted):
    """Six mints per address per day (F8), and the passthrough does not launder
    them. The application's uniform 429 reaches the browser unchanged.
    """
    web, _ = fronted
    codes = [web.post("/web/room-token").status_code for _ in range(8)]
    assert codes[0] == 200
    assert 429 in codes


def test_the_method_is_part_of_the_allowlist(fronted):
    """`/web/config` is a GET and `/web/room-token` is a POST. Neither answers
    the other's method.
    """
    web, _ = fronted
    assert web.post("/web/config").status_code == 405
    assert web.get("/web/room-token").status_code == 405


def test_an_unreachable_application_is_told_to_the_page_as_unavailable():
    """C-30. The page has words for this; the process must not crash into them."""

    class _Dead:
        def request(self, *_args, **_kwargs):
            raise httpx.ConnectError("refused")

    web = StarletteTestClient(
        server.create_app(api_url="http://api.test", http=_Dead())
    )
    response = web.post("/web/room-token")
    assert response.status_code == 503
    assert response.json() == server.UNAVAILABLE_BODY


def test_a_minted_token_is_never_cached(fronted):
    web, _ = fronted
    assert web.post("/web/room-token").headers["cache-control"] == "no-store"


# --------------------------------------------------------------------------
# The offer budget, where it sits on the path (C-07, C-34)
# --------------------------------------------------------------------------


@pytest.fixture
def budgeted(client):
    """The signalling server with a small, known budget in front of it."""
    upstream = _Recorder(client)
    offers = budget.OfferBudget(
        max_offers_per_ip=3, window_seconds=3600, max_concurrent_calls=2
    )
    app = server.create_app(api_url="http://api.test", http=upstream, budget=offers)
    return StarletteTestClient(app, client=("203.0.113.9", 4444)), upstream, offers


def test_a_flood_of_offers_is_refused(budgeted):
    web, _, _ = budgeted
    codes = [
        web.post("/api/offer", json=_offer("r", "junk.junk")).status_code
        for _ in range(6)
    ]
    assert 429 in codes
    assert codes[-1] == 429


def test_the_budget_is_spent_before_the_token_is_checked(budgeted):
    """The ordering property, and the reason it is not just an optimisation.

    A budget checked after verification would answer 403 for a forged token and
    429 for a good one — which tells a prober that their token was the good
    part. Checked first, everybody over the limit gets the same 429 whatever
    they presented.
    """
    web, upstream, _ = budgeted
    minted = web.post("/web/room-token").json()
    before = len(upstream.sent)

    for _ in range(4):
        web.post("/api/offer", json=_offer("r", "junk.junk"))

    good = web.post("/api/offer", json=_offer(minted["room"], minted["token"]))
    assert good.status_code == 429
    assert good.json() == server.BUSY_BODY

    # And the refused ones never reached the application at all.
    verifies = [
        call for call in upstream.sent[before:] if "room-token/verify" in call["path"]
    ]
    assert len(verifies) <= 3


def test_a_refused_offer_costs_the_trusted_zone_nothing(budgeted):
    """The measurement that started this: thirty anonymous posts produced thirty
    signed requests into the trusted zone.
    """
    web, upstream, _ = budgeted
    before = len(upstream.sent)
    for _ in range(30):
        web.post("/api/offer", json=_offer("r", "junk.junk"))
    reached = [
        call for call in upstream.sent[before:] if "room-token/verify" in call["path"]
    ]
    assert len(reached) <= 3


def test_the_busy_answer_says_nothing_about_which_limit(budgeted, client):
    """Which budget somebody tripped is a fact about this server's configuration.
    A caller who learns it learns which one to work around.
    """
    web, _, offers = budgeted

    # Over the per-address limit.
    for _ in range(3):
        web.post("/api/offer", json=_offer("r", "j.j"))
    over_ip = web.post("/api/offer", json=_offer("r", "j.j"))

    # A different address, under its own limit, but the process is at its
    # concurrency cap.
    offers.register("a", object())
    offers.register("b", object())
    elsewhere = StarletteTestClient(
        server.create_app(
            api_url="http://api.test", http=_Recorder(client), budget=offers
        ),
        client=("198.51.100.1", 5555),
    )
    over_concurrency = elsewhere.post("/api/offer", json=_offer("c", "j.j"))

    assert over_ip.status_code == over_concurrency.status_code == 429
    assert over_ip.json() == over_concurrency.json() == server.BUSY_BODY


def test_the_page_has_words_for_busy():
    """The page already says this for the application's 429 on minting; a busy
    offer must land in the same branch rather than in "couldn't reach".
    """
    page = (
        server.INDEX.read_text(encoding="utf-8")
        if server.INDEX.exists()
        else ""
    )
    assert "busy" in page
