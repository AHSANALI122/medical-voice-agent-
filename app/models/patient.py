from __future__ import annotations

from datetime import datetime

from sqlalchemy import Index, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UtcDateTime, utcnow


class Patient(Base):
    """The name is PHI (C-08). It is stored encrypted with a per-row nonce and a
    key_id, alongside a normalized form used only for parameterized matching
    (C-35). There is no reason-for-visit column and there never will be — the
    absence is the control.
    """

    __tablename__ = "patients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    name_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    key_id: Mapped[str] = mapped_column(String(16), nullable=False)
    name_normalized: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False, default=utcnow)

    __table_args__ = (Index("ix_patients_name_normalized", "name_normalized"),)
