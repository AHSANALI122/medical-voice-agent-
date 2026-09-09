from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, TypeDecorator
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class UtcDateTime(TypeDecorator):
    """Stores tz-aware datetimes as naive UTC and hands them back tz-aware.

    All timestamps in this system are UTC (F0). Clinic-local time is a
    presentation concern resolved at the edges.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime reached the database layer")
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
