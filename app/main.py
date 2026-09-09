"""FastAPI application.

Boot does five things, in order, and refuses to serve if any of them fails:
  1. reads configuration (which rejects DEMO_MODE under ENV=production);
  2. logs whether the database file was found or is being created — silent data
     loss is the failure mode that costs hours, and one line makes it obvious;
  3. seeds idempotently and asserts the synthetic marker (C-17);
  4. loads the doctor whitelist into memory (C-11);
  5. purges observability events past their 30-day retention (F11).

The purge runs at boot rather than on a timer because the deployment has no
scheduler and a free-tier restart is the only reliable recurring event there is.
On this ephemeral database it will usually find nothing, which is the point: it
has to work on the day the database is not ephemeral.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from app.config import get_settings
from app.db.base import database_existed, get_engine, session_scope
from app.db.seed import assert_synthetic, seed
from app.models import Base
from app.services import observability
from app.services.directory import load_whitelist
from app.tools.router import router as tools_router
from app.web.router import router as web_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("voicebook")


def bootstrap() -> None:
    settings = get_settings()
    existed = database_existed(settings.vb_database_path)
    log.info(
        "db_boot path=%s state=%s note=%s",
        settings.vb_database_path,
        "found" if existed else "created",
        "demo data resets on redeploy",
    )

    engine = get_engine()
    Base.metadata.create_all(engine)

    with session_scope() as db:
        seed(db)
        assert_synthetic(db)
        entries = load_whitelist(db)
        purged = observability.purge(db)
    log.info("directory_loaded doctors=%d", len(entries))
    log.info(
        "events_purged rows=%d retention_days=%d",
        purged,
        observability.RETENTION_DAYS,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="VoiceBook",
        version="3.0",
        lifespan=lifespan,
        # The schema is a map of the attack surface; it stays off in production.
        openapi_url=None if settings.env == "production" else "/openapi.json",
    )
    app.include_router(tools_router)
    app.include_router(web_router)

    @app.middleware("http")
    async def observe_tool_calls(request: Request, call_next):
        """One event row per tool call (F11).

        Three things worth knowing about the shape of this.

        It writes on its own database session, after the response exists. An
        event must never be able to roll back the mutation it describes — that
        is the exact opposite of the audit rule (F17), and deliberately so.

        A failure to write one is swallowed. Telemetry that can take the service
        down is worse than no telemetry.

        The correlation id goes out on every response, including the failures.
        It is the one value a caller can quote back at a support channel, and it
        identifies a request rather than a person.
        """
        if not request.url.path.startswith("/tools/"):
            return await call_next(request)

        seen = observability.observation(request)
        started = time.perf_counter()
        response = await call_next(request)
        latency_ms = (time.perf_counter() - started) * 1000

        try:
            with session_scope() as db:
                event = observability.record_tool_call(
                    db,
                    correlation_id=seen.correlation_id,
                    tool=observability.tool_from_path(request.url.path),
                    status_code=response.status_code,
                    latency_ms=latency_ms,
                    channel=seen.channel,
                    session_id=seen.session_id,
                    turn=seen.turn,
                    escalated=seen.escalated,
                )
                db.flush()
                log.info(observability.log_line(event))
        except Exception:
            log.warning(
                "observability_write_failed correlation_id=%s", seen.correlation_id
            )

        response.headers["x-correlation-id"] = seen.correlation_id
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
