"""Constrained types (section 7).

These validate shape. None of them looks anything up, touches the database, or
decides permission (C-36). A perfectly-formed request from a stranger is still a
perfectly-formed request from a stranger; authorization happens later, in a
dependency, and returns 403 rather than 422.
"""

from __future__ import annotations

import re
import uuid
from datetime import date as Date
from datetime import datetime, timezone
from typing import Annotated

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field

from app.config import get_settings
from app.security.normalize import normalize_name

# Validation horizon. Deliberately wider than the offer horizon (C-29): the slot
# engine decides what is bookable, this type only rejects the absurd.
MAX_DATE_HORIZON_DAYS = 60

_NAME_ALLOWED = re.compile(r"^[A-Za-zÀ-ɏ' \-]+$")


class StrictModel(BaseModel):
    """Every model on the wire: strict types, unknown fields rejected."""

    model_config = ConfigDict(strict=True, extra="forbid")


def _check_name(value: str) -> str:
    stripped = value.strip()
    if not 1 <= len(stripped) <= 60:
        raise ValueError("name must be 1 to 60 characters")
    if not _NAME_ALLOWED.match(stripped):
        raise ValueError("name may contain only letters, spaces, hyphens and apostrophes")
    if not normalize_name(stripped):
        raise ValueError("name normalizes to nothing")
    return stripped


PatientName = Annotated[str, AfterValidator(_check_name)]


def _parse_date(value: object) -> object:
    """Accept an ISO date string in both python and JSON validation modes.

    Strict mode would otherwise reject the string form that every HTTP client
    actually sends.
    """
    if isinstance(value, str):
        try:
            return Date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("date must be ISO yyyy-mm-dd") from exc
    return value


def _check_appointment_date(value: Date) -> Date:
    settings = get_settings()
    today = datetime.now(timezone.utc).astimezone(settings.clinic_tz).date()
    if value < today:
        raise ValueError("date is in the past")
    if (value - today).days > MAX_DATE_HORIZON_DAYS:
        raise ValueError(f"date is beyond the {MAX_DATE_HORIZON_DAYS}-day horizon")
    return value


AppointmentDate = Annotated[
    Date, BeforeValidator(_parse_date), AfterValidator(_check_appointment_date)
]

# A date used only for lookup, not for creating anything: same shape rules, no
# future requirement, because a caller may cancel an appointment later today.
LookupDate = Annotated[Date, BeforeValidator(_parse_date)]


def _check_reference(value: str) -> str:
    if not re.fullmatch(r"[0-9]{4}", value):
        raise ValueError("reference must be exactly 4 digits")
    return value


BookingRef = Annotated[str, AfterValidator(_check_reference)]


def _check_uuid(value: str) -> str:
    try:
        uuid.UUID(value)
    except ValueError as exc:
        raise ValueError("idempotency key must be a UUID") from exc
    return value


IdempotencyKey = Annotated[str, AfterValidator(_check_uuid)]

# Ordinals, never database identifiers (C-04). The server resolves an ordinal
# against the offer list it made to this session; the model never names a row.
Ordinal = Annotated[int, Field(ge=1, le=20)]

SessionId = Annotated[str, Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]

SpokenFragment = Annotated[str, Field(min_length=1, max_length=64)]

SpecialtyQuery = Annotated[str, Field(min_length=2, max_length=40)]
