from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

SEED_MARKER_KEY = "seed_marker"
SEED_MARKER_VALUE = "synthetic-v3"


class Meta(Base):
    """Key/value boot facts.

    Carries the synthetic-seed marker (C-17): the app refuses to serve a
    database that was not built from the synthetic seed, so real patient data
    can never be quietly attached to a public demo.
    """

    __tablename__ = "meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
