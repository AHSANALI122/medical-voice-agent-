from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UtcDateTime, utcnow

CHANNEL_WEB = "web"
CHANNEL_PHONE = "phone"
CHANNEL_TESTER = "tester"
CHANNELS = (CHANNEL_WEB, CHANNEL_PHONE, CHANNEL_TESTER)


class Session(Base):
    """A conversation in progress.

    Deliberately carries no tier and no patient_id (C-38): nothing stored here
    grants standing access to any record. A session proves only that a
    conversation is open on this channel.

    digit_buffer is the server-side reference buffer from section 6.4. It holds
    what the caller is currently saying, never an issued reference.

    offers_json is the server-side ordinal table (C-04): tools speak in ordinals
    and the server resolves them to database ids here, so no database identifier
    ever crosses the wire.
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)

    digit_buffer: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    digit_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    digits_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    offers_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    turn_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consent_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)

    __table_args__ = (
        CheckConstraint("channel in ('web','phone','tester')", name="ck_session_channel"),
    )
