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
):
    os.environ.setdefault(
        name, base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    )
os.environ["VB_DATABASE_PATH"] = ":memory:"

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

    def __init__(self, client: TestClient, channel: str = "web") -> None:
        self.client = client
        self.channel = channel

    def post(self, path: str, payload: dict, *, channel: str | None = None):
        channel = channel or self.channel
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        secret = get_settings().channel_secret(channel)
        signature = request_auth.sign(secret, timestamp, nonce, body)
        return self.client.post(
            path,
            content=body,
            headers={
                "content-type": "application/json",
                "x-vb-channel": channel,
                "x-vb-timestamp": timestamp,
                "x-vb-nonce": nonce,
                "x-vb-signature": signature,
            },
        )

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
