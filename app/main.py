"""FastAPI application.

Boot does four things, in order, and refuses to serve if any of them fails:
  1. reads configuration (which rejects DEMO_MODE under ENV=production);
  2. logs whether the database file was found or is being created — silent data
     loss is the failure mode that costs hours, and one line makes it obvious;
  3. seeds idempotently and asserts the synthetic marker (C-17);
  4. loads the doctor whitelist into memory (C-11).
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.db.base import database_existed, get_engine, session_scope
from app.db.seed import assert_synthetic, seed
from app.models import Base
from app.services.directory import load_whitelist
from app.tools.router import router as tools_router

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
    log.info("directory_loaded doctors=%d", len(entries))


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

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
