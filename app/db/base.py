"""Engine and session factory.

WAL mode and foreign-key enforcement are set per connection, not once at
creation, because SQLite applies PRAGMA per connection and the pool opens more
than one.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import sessionmaker

from app.config import get_settings

log = logging.getLogger("voicebook.db")

_engine: Engine | None = None
_SessionLocal: sessionmaker[OrmSession] | None = None


def _configure_connection(dbapi_conn, _record) -> None:
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def build_engine(database_path: str) -> Engine:
    if database_path == ":memory:":
        # One shared connection, or every thread gets its own empty database.
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
    else:
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite+pysqlite:///{database_path}"
        engine = create_engine(url, future=True)
    event.listen(engine, "connect", _configure_connection)
    return engine


def database_existed(database_path: str) -> bool:
    """F0 boot check: was the file found, or is this a cold rebuild?"""
    if database_path == ":memory:":
        return False
    return os.path.exists(database_path)


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        settings = get_settings()
        _engine = build_engine(settings.vb_database_path)
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def get_sessionmaker() -> sessionmaker[OrmSession]:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


def set_engine(engine: Engine) -> None:
    """Test hook: point the process at a different engine."""
    global _engine, _SessionLocal
    _engine = engine
    _SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def reset_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Iterator[OrmSession]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def db_session() -> Iterator[OrmSession]:
    """FastAPI dependency."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()
