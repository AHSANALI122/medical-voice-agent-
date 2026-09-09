from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UtcDateTime, utcnow

STATUS_ACTIVE = "active"
STATUS_CANCELLED = "cancelled"
STATUS_COMPLETED = "completed"


class Appointment(Base):
    """The booking reference lives here only as an HMAC (F0, section 5.1).

    Two partial unique indexes carry real weight:
      - one slot per doctor while active: the database, not the application's
        free-slot check, decides the concurrency race (C-12);
      - one active appointment per reference HMAC, so a reference may be reused
        after an appointment leaves active status but never collides while live.
    """

    __tablename__ = "appointments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    doctor_id: Mapped[int] = mapped_column(ForeignKey("doctors.id"), nullable=False, index=True)
    patient_id: Mapped[int] = mapped_column(ForeignKey("patients.id"), nullable=False, index=True)

    slot_start_utc: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, index=True)
    slot_end_utc: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_ACTIVE)

    reference_hmac: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    reference_key_id: Mapped[str] = mapped_column(String(16), nullable=False)

    # No failed-attempt counter and no lock column live here on purpose. The
    # brute-force budget is charged to the caller (source IP plus the name they
    # asked about) in app.security.rate_limit, because a counter on the record
    # lets a stranger who knows a name and a date lock a real patient out of
    # their own booking (C-34).

    # F15: idempotency key, scoped to the issuing channel.
    idempotency_key: Mapped[str | None] = mapped_column(String(96), nullable=True)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)
    cancelled_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status in ('active','cancelled','completed')", name="ck_appointment_status"
        ),
        Index(
            "uq_appointment_doctor_slot_active",
            "doctor_id",
            "slot_start_utc",
            unique=True,
            sqlite_where=text("status = 'active'"),
        ),
        Index(
            "uq_appointment_reference_active",
            "reference_hmac",
            unique=True,
            sqlite_where=text("status = 'active'"),
        ),
        Index("uq_appointment_idempotency", "idempotency_key", unique=True),
    )
