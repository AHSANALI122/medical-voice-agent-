"""Slot engine (F1).

Slots come from availability rules, minus booked appointments, minus blackouts,
minus anything inside the booking lead time.

Two limits are security, not ergonomics (C-29): at most five slots come back and
the horizon is capped, so this endpoint cannot be walked to reconstruct a
doctor's schedule.

DST: rules are expressed in clinic-local minutes and each candidate day is
localized independently, so a day that gains or loses an hour produces the
correct wall-clock slots rather than a shifted grid.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date as Date
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.models import (
    RULE_AVAILABLE,
    RULE_BLACKOUT,
    STATUS_ACTIVE,
    Appointment,
    AvailabilityRule,
)


@dataclass(frozen=True)
class Slot:
    start_utc: datetime
    end_utc: datetime
    doctor_id: int

    def local(self, tz) -> datetime:
        return self.start_utc.astimezone(tz)


def _localize(day: Date, minute_of_day: int, tz) -> datetime:
    """Clinic-local wall clock to UTC, resolved per day so DST is handled."""
    base = datetime.combine(day, time(0, 0), tzinfo=tz)
    return (base + timedelta(minutes=minute_of_day)).astimezone(timezone.utc)


def _rule_slots(rule: AvailabilityRule, day: Date, tz) -> list[tuple[datetime, datetime]]:
    out: list[tuple[datetime, datetime]] = []
    minute = rule.start_minute
    while minute + rule.slot_minutes <= rule.end_minute:
        start = _localize(day, minute, tz)
        end = _localize(day, minute + rule.slot_minutes, tz)
        out.append((start, end))
        minute += rule.slot_minutes
    return out


def available_slots(
    db: OrmSession,
    *,
    doctor_id: int,
    from_date: Date | None = None,
    on_date: Date | None = None,
    now: datetime | None = None,
    limit: int | None = None,
) -> list[Slot]:
    """Free slots for one doctor, ordered earliest first.

    Beyond-horizon requests return an empty list, not an error (F1 acceptance):
    "nothing that week" is an answer, and raising would tell a prober that their
    date parsed fine.
    """
    settings = get_settings()
    tz = settings.clinic_tz
    now = now or datetime.now(timezone.utc)
    limit = settings.max_slots_returned if limit is None else limit

    horizon_end = (now + timedelta(days=settings.slot_horizon_days)).astimezone(tz).date()
    earliest_start = now + timedelta(minutes=settings.booking_lead_time_minutes)

    if on_date is not None:
        if on_date > horizon_end or on_date < now.astimezone(tz).date():
            return []
        days = [on_date]
    else:
        start_day = from_date or now.astimezone(tz).date()
        if start_day > horizon_end:
            return []
        start_day = max(start_day, now.astimezone(tz).date())
        days = []
        cursor = start_day
        while cursor <= horizon_end:
            days.append(cursor)
            cursor += timedelta(days=1)

    rules = (
        db.execute(
            select(AvailabilityRule).where(AvailabilityRule.doctor_id == doctor_id)
        )
        .scalars()
        .all()
    )
    open_rules = [r for r in rules if r.kind == RULE_AVAILABLE]
    blackouts = [r for r in rules if r.kind == RULE_BLACKOUT]

    window_start = _localize(days[0], 0, tz)
    window_end = _localize(days[-1], 0, tz) + timedelta(days=1)

    booked = set(
        db.execute(
            select(Appointment.slot_start_utc)
            .where(Appointment.doctor_id == doctor_id)
            .where(Appointment.status == STATUS_ACTIVE)
            .where(Appointment.slot_start_utc >= window_start)
            .where(Appointment.slot_start_utc < window_end)
        )
        .scalars()
        .all()
    )

    found: list[Slot] = []
    seen: set[datetime] = set()
    for day in days:
        day_blackouts = [b for b in blackouts if _blackout_applies(b, day)]
        for rule in open_rules:
            if rule.weekday is not None and rule.weekday != day.weekday():
                continue
            for start, end in _rule_slots(rule, day, tz):
                if start < earliest_start:
                    continue
                if start in seen or start in booked:
                    continue
                if any(_blacked_out(b, day, start, end, tz) for b in day_blackouts):
                    continue
                seen.add(start)
                found.append(Slot(start_utc=start, end_utc=end, doctor_id=doctor_id))
        if len(found) >= limit and on_date is None:
            break

    found.sort(key=lambda s: s.start_utc)
    return found[:limit]


def _blackout_applies(blackout: AvailabilityRule, day: Date) -> bool:
    """A blackout pins to one date, to one weekday, or to every day."""
    if blackout.blackout_date is not None:
        return blackout.blackout_date == day.isoformat()
    if blackout.weekday is not None:
        return blackout.weekday == day.weekday()
    return True


def _blacked_out(
    blackout: AvailabilityRule, day: Date, start: datetime, end: datetime, tz
) -> bool:
    b_start = _localize(day, blackout.start_minute, tz)
    b_end = _localize(day, blackout.end_minute, tz)
    return start < b_end and end > b_start
