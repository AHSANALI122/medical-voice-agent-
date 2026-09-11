from __future__ import annotations

import base64
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("ENV", "test")
os.environ.setdefault("DEMO_MODE", "true")
for name in (
    "VB_ENCRYPTION_KEY",
    "VB_REFERENCE_HMAC_KEY",
    "VB_CHANNEL_SECRET_WEB",
    "VB_CHANNEL_SECRET_PHONE",
    "VB_CHANNEL_SECRET_TESTER",
    "VB_ROOM_TOKEN_KEY",
):
    os.environ.setdefault(
        name, base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    )
os.environ["VB_DATABASE_PATH"] = ":memory:"

# The F8 budgets, pinned to the values `app/config.py` ships.
#
# Assigned, not `setdefault`: pydantic-settings ranks the real environment above
# `.env`, and `.env` is gitignored and local. Without these the suite silently
# tests whatever budget a developer happened to raise to get the tester working
# — `test_a_throttled_call_is_recorded_as_throttled` hardcodes 3, and the F8
# tests that do read the limit from settings still need it small enough to stay
# inside the seeded availability. A security suite that means something
# different on every machine is worse than one that is merely strict, so the
# numbers under test live here, next to the assertions that depend on them.
#
# Raising a budget in your own `.env` is expected and supported; it is how the
# text-mode loop in spec §10 stays usable on one IP. It must not reach here.
os.environ["ABUSE_WINDOW_HOURS"] = "24"
os.environ["MAX_SESSIONS_PER_IP_PER_DAY"] = "3"
os.environ["MAX_SESSIONS_PER_CALL_ID_PER_DAY"] = "3"
os.environ["MAX_BOOKINGS_PER_NAME_PER_DAY"] = "3"
os.environ["MAX_BOOKINGS_PER_DAY_GLOBAL"] = "200"
os.environ["MAX_REFERENCE_ATTEMPTS"] = "5"
os.environ["REFERENCE_LOCK_MINUTES"] = "60"
os.environ["MAX_ROOM_TOKENS_PER_IP_PER_DAY"] = "6"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session as OrmSession  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.db import base as db_base  # noqa: E402
from app.db.seed import seed  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Base  # noqa: E402
from app.security import request_auth  # noqa: E402
from app.services import booking, directory  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_database():
    """A new in-memory database per test. The system is ephemeral by design, so
    the tests get the same posture the deployment has.
    """
    db_base.reset_engine()
    engine = db_base.build_engine(":memory:")
    db_base.set_engine(engine)
    Base.metadata.create_all(engine)
    with db_base.session_scope() as db:
        seed(db)
        directory.load_whitelist(db)
    request_auth.get_replay_cache().clear()
    booking.forget_references()
    yield
    db_base.reset_engine()


@pytest.fixture
def db() -> OrmSession:
    session = db_base.get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    # The app's own lifespan would rebuild the database; the fixture already
    # built one, so the client is created without running it.
    return TestClient(app)


class SignedClient:
    """Signs like any external caller would (F4). The tests have no privileged
    path into the API, which is the point of C-13.
    """

    def __init__(
        self, client: TestClient, channel: str = "web", call_id: str | None = None
    ) -> None:
        self.client = client
        self.channel = channel
        self.call_id = call_id

    def post(
        self,
        path: str,
        payload: dict,
        *,
        channel: str | None = None,
        call_id: str | None = None,
    ):
        channel = channel or self.channel
        call_id = call_id if call_id is not None else self.call_id
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        secret = get_settings().channel_secret(channel)
        signature = request_auth.sign(secret, timestamp, nonce, body, call_id or "")
        headers = {
            "content-type": "application/json",
            "x-vb-channel": channel,
            "x-vb-timestamp": timestamp,
            "x-vb-nonce": nonce,
            "x-vb-signature": signature,
        }
        if call_id:
            headers["x-vb-call-id"] = call_id
        return self.client.post(path, content=body, headers=headers)

    def raw_post(self, path: str, body: bytes, headers: dict):
        return self.client.post(path, content=body, headers=headers)


@pytest.fixture
def api(client) -> SignedClient:
    return SignedClient(client)


@pytest.fixture
def other_ip_api(app) -> SignedClient:
    """A second caller from a different source address.

    Abuse budgets are keyed on the source IP (C-34), so proving that one
    caller's lockout does not reach another one needs two addresses, not two
    sessions.
    """
    return SignedClient(TestClient(app, client=("198.51.100.4", 51000)))


@pytest.fixture
def session_id(api) -> str:
    response = api.post("/tools/create_session", {"consent_given": True})
    assert response.status_code == 200
    return response.json()["session_id"]


@pytest.fixture
def booked(api, session_id):
    """Book one appointment and hand back everything the tests need."""

    def _book(name: str = "Ahmed Khan", specialty: str = "Cardiology", slot_ordinal: int = 1):
        doctors = api.post(
            "/tools/search_doctors", {"session_id": session_id, "specialty": specialty}
        ).json()["results"]
        assert doctors
        api.post(
            "/tools/get_available_slots",
            {"session_id": session_id, "doctor_ordinal": 1},
        )
        result = api.post(
            "/tools/book_appointment",
            {
                "session_id": session_id,
                "slot_ordinal": slot_ordinal,
                "patient_name": name,
                "idempotency_key": str(uuid.uuid4()),
            },
        )
        assert result.status_code == 200, result.text
        payload = result.json()
        local = datetime.fromisoformat(payload["starts_at_local"])
        return {
            "reference": payload["reference"],
            "date": local.date().isoformat(),
            "name": name,
            "doctor_name": payload["doctor_name"],
        }

    return _book


@pytest.fixture
def clinic_now():
    return datetime.now(timezone.utc)


@pytest.fixture
def tomorrow(clinic_now):
    return (clinic_now.astimezone(get_settings().clinic_tz) + timedelta(days=1)).date()
