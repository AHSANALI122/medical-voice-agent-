"""Synthetic seed (F0, C-17, C-26).

The database is ephemeral by decision. It rebuilds from this seed on every cold
start, so seeding is idempotent and automatic — never a manual step, because a
free-tier sleep cycle restarts the app with nobody watching.

Everything here is invented. No real doctor, no real patient, no real phone
number. The synthetic marker row is what boot asserts on: an unmarked database
is refused rather than served, so real data cannot quietly end up behind a
public demo.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.models import (
    RULE_AVAILABLE,
    RULE_BLACKOUT,
    SEED_MARKER_KEY,
    SEED_MARKER_VALUE,
    AvailabilityRule,
    Doctor,
    Meta,
)

log = logging.getLogger("voicebook.seed")

# 9 doctors across 6 specialties (F0 acceptance: at least 8 across at least 5).
SEED_DOCTORS: list[tuple[str, str]] = [
    ("Dr. Ayesha Siddiqui", "Cardiology"),
    ("Dr. Bilal Ahmed", "Cardiology"),
    ("Dr. Farah Nadeem", "Dermatology"),
    ("Dr. Hamza Iqbal", "Orthopedics"),
    ("Dr. Iman Raza", "Pediatrics"),
    ("Dr. Junaid Malik", "Pediatrics"),
    ("Dr. Kiran Shah", "Neurology"),
    ("Dr. Laiba Farooq", "General Medicine"),
    ("Dr. Moiz Haider", "General Medicine"),
]

MORNING = (9 * 60, 12 * 60)
AFTERNOON = (14 * 60, 17 * 60)
SLOT_MINUTES = 30


def _seed_marker(db: OrmSession) -> Meta | None:
    return db.get(Meta, SEED_MARKER_KEY)


def is_seeded(db: OrmSession) -> bool:
    marker = _seed_marker(db)
    return marker is not None and marker.value == SEED_MARKER_VALUE


def seed(db: OrmSession) -> bool:
    """Idempotent. Returns True if this call created the seed data."""
    if is_seeded(db):
        log.info("seed_present marker=%s doctors=%d", SEED_MARKER_VALUE, _doctor_count(db))
        return False

    for index, (full_name, specialty) in enumerate(SEED_DOCTORS):
        doctor = Doctor(full_name=full_name, specialty=specialty, active=True)
        db.add(doctor)
        db.flush()

        # Weekdays only; alternate which half of the day each doctor works so
        # the demo has genuinely different schedules rather than one grid.
        for weekday in range(0, 5):
            windows = [MORNING, AFTERNOON] if index % 3 == 0 else [
                MORNING if (index + weekday) % 2 == 0 else AFTERNOON
            ]
            for start, end in windows:
                db.add(
                    AvailabilityRule(
                        doctor_id=doctor.id,
                        kind=RULE_AVAILABLE,
                        weekday=weekday,
                        start_minute=start,
                        end_minute=end,
                        slot_minutes=SLOT_MINUTES,
                    )
                )

    # One recurring blackout so the "minus blackouts" path is exercised by the
    # seed itself and not only by tests: every doctor keeps the last half hour
    # before noon free for walk-ins.
    for doctor_id in db.execute(select(Doctor.id)).scalars().all():
        db.add(
            AvailabilityRule(
                doctor_id=doctor_id,
                kind=RULE_BLACKOUT,
                weekday=None,
                blackout_date=None,
                start_minute=11 * 60 + 30,
                end_minute=12 * 60,
                slot_minutes=SLOT_MINUTES,
            )
        )

    db.add(Meta(key=SEED_MARKER_KEY, value=SEED_MARKER_VALUE))
    db.commit()
    log.info("seed_created marker=%s doctors=%d", SEED_MARKER_VALUE, len(SEED_DOCTORS))
    return True


def _doctor_count(db: OrmSession) -> int:
    return len(db.execute(select(Doctor.id)).scalars().all())


class UnseededDatabase(RuntimeError):
    pass


def assert_synthetic(db: OrmSession) -> None:
    """Boot assertion: refuse to serve a database that is not the synthetic one."""
    if not is_seeded(db):
        raise UnseededDatabase(
            "database is missing the synthetic-seed marker; refusing to start"
        )
