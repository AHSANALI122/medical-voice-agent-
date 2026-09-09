"""Run the eval suite standalone: `uv run python -m evals`.

Builds its own in-memory database and its own signed client, so it needs no
running server and no real keys — the same posture the test suite runs in. The
client signs like any external caller; there is no privileged path here either.

`tests/adversarial/test_f11_evals.py` is what actually gates CI. This entry
point exists so the suite can be read as a report rather than as pytest output.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import time
import uuid


def _ensure_dev_environment() -> None:
    os.environ.setdefault("ENV", "development")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the VoiceBook eval suite.")
    parser.add_argument(
        "--transcripts",
        action="store_true",
        help="include the fenced caller transcripts in the report",
    )
    args = parser.parse_args(argv)

    _ensure_dev_environment()

    from fastapi.testclient import TestClient

    from app.config import get_settings
    from app.db import base as db_base
    from app.db.seed import seed
    from app.main import create_app
    from app.models import Base
    from app.security import request_auth
    from app.services import booking, directory
    from evals.report import render
    from evals.runner import run
    from evals.scenarios import ALL_SCENARIOS

    class SigningCaller:
        def __init__(self, client: TestClient) -> None:
            self.client = client

        def post(self, path: str, payload: dict, *, channel: str = "web"):
            body = json.dumps(payload).encode()
            timestamp = str(int(time.time()))
            nonce = uuid.uuid4().hex
            secret = get_settings().channel_secret(channel)
            return self.client.post(
                path,
                content=body,
                headers={
                    "content-type": "application/json",
                    "x-vb-channel": channel,
                    "x-vb-timestamp": timestamp,
                    "x-vb-nonce": nonce,
                    "x-vb-signature": request_auth.sign(secret, timestamp, nonce, body, ""),
                },
            )

    app = create_app()
    results = []
    for scenario in ALL_SCENARIOS:
        # A fresh database per scenario: the deployment is ephemeral by decision
        # (F0), so the evals get the posture the deployment has.
        db_base.reset_engine()
        engine = db_base.build_engine(":memory:")
        db_base.set_engine(engine)
        Base.metadata.create_all(engine)
        with db_base.session_scope() as setup:
            seed(setup)
            directory.load_whitelist(setup)
        request_auth.get_replay_cache().clear()
        booking.forget_references()

        db = db_base.get_sessionmaker()()
        try:
            results.append(
                run(scenario, caller=SigningCaller(TestClient(app)), db=db)
            )
        finally:
            db.close()

    print(render(results, include_transcripts=args.transcripts))
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
