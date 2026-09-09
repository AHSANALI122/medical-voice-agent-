from __future__ import annotations

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

# An availability rule is either a recurring open window or a blackout that
# subtracts from it. Keeping both in one table keeps the F0 table list exact.
RULE_AVAILABLE = "available"
RULE_BLACKOUT = "blackout"


class Doctor(Base):
    __tablename__ = "doctors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    specialty: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    rules: Mapped[list["AvailabilityRule"]] = relationship(back_populates="doctor")

    __table_args__ = (Index("ix_doctors_active_specialty", "active", "specialty"),)


class AvailabilityRule(Base):
    __tablename__ = "availability_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    doctor_id: Mapped[int] = mapped_column(
        ForeignKey("doctors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default=RULE_AVAILABLE)
    # Recurring weekly window, clinic-local. weekday: Monday=0 .. Sunday=6.
    weekday: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Blackouts pin to one clinic-local calendar date (ISO yyyy-mm-dd).
    blackout_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    start_minute: Mapped[int] = mapped_column(Integer, nullable=False)
    end_minute: Mapped[int] = mapped_column(Integer, nullable=False)
    slot_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    doctor: Mapped[Doctor] = relationship(back_populates="rules")

    __table_args__ = (
        CheckConstraint("kind in ('available','blackout')", name="ck_rule_kind"),
        CheckConstraint("start_minute >= 0 and end_minute <= 1440", name="ck_rule_bounds"),
        CheckConstraint("end_minute > start_minute", name="ck_rule_order"),
    )
