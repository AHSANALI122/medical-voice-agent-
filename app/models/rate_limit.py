from __future__ import annotations

from datetime import datetime

from sqlalchemy import Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UtcDateTime, utcnow


class RateLimitBucket(Base):
    """Persisted so a reconnect resets no budget (C-23, C-34).

    Scope is never session_id: that value resets whenever the caller reconnects,
    which is exactly the reset an abuser wants.
    """

    __tablename__ = "rate_limit_buckets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    bucket_key: Mapped[str] = mapped_column(String(128), nullable=False)
    window_start_utc: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)

    __table_args__ = (
        Index("uq_bucket", "scope", "bucket_key", "window_start_utc", unique=True),
    )
