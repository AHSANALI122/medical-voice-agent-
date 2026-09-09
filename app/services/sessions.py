"""Session lifecycle and the server-side offer table.

A session is a conversation, not a credential. It records where the caller is in
the flow and what the server last offered them, so ordinals can be resolved
without any database identifier crossing the wire (C-04). It stores no patient
id and no tier, and possessing one grants access to nothing (C-38).
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.models import Session
from app.services.state_machine import State, entry_state

OFFER_DOCTORS = "doctors"
OFFER_SLOTS = "slots"


@dataclass(frozen=True)
class SlotOfferRecord:
    doctor_id: int
    doctor_name: str
    start_utc: str
    end_utc: str


def new_session_id() -> str:
    return secrets.token_urlsafe(24)


def create_session(db: OrmSession, *, channel: str, consent: bool = False) -> Session:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    session = Session(
        id=new_session_id(),
        channel=channel,
        state=entry_state().value,
        digit_buffer="",
        digit_retries=0,
        digits_confirmed=False,
        offers_json="{}",
        turn_count=0,
        consent_at=now if consent else None,
        created_at=now,
        expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
    )
    db.add(session)
    db.flush()
    return session


def load_live_session(
    db: OrmSession, *, session_id: str, channel: str, now: datetime | None = None
) -> Session | None:
    """A session is usable only by the channel that opened it, and only before
    it expires. A session id lifted from a web transcript is worthless on the
    phone channel.
    """
    now = now or datetime.now(timezone.utc)
    session = db.get(Session, session_id)
    if session is None:
        return None
    if session.channel != channel:
        return None
    if session.expires_at <= now:
        return None
    return session


def set_state(session: Session, state: State) -> None:
    session.state = state.value


def get_state(session: Session) -> State:
    return State(session.state)


def _offers(session: Session) -> dict:
    try:
        return json.loads(session.offers_json)
    except (TypeError, ValueError):
        return {}


def record_doctor_offers(session: Session, doctor_ids: list[int]) -> None:
    offers = _offers(session)
    offers[OFFER_DOCTORS] = doctor_ids
    # A fresh doctor list invalidates any slot list built from the old one.
    offers.pop(OFFER_SLOTS, None)
    session.offers_json = json.dumps(offers)


def resolve_doctor_ordinal(session: Session, ordinal: int) -> int | None:
    doctor_ids = _offers(session).get(OFFER_DOCTORS) or []
    if 1 <= ordinal <= len(doctor_ids):
        return int(doctor_ids[ordinal - 1])
    return None


def record_slot_offers(session: Session, slots: list[SlotOfferRecord]) -> None:
    offers = _offers(session)
    offers[OFFER_SLOTS] = [
        {
            "doctor_id": s.doctor_id,
            "doctor_name": s.doctor_name,
            "start_utc": s.start_utc,
            "end_utc": s.end_utc,
        }
        for s in slots
    ]
    session.offers_json = json.dumps(offers)


def resolve_slot_ordinal(session: Session, ordinal: int) -> SlotOfferRecord | None:
    slots = _offers(session).get(OFFER_SLOTS) or []
    if 1 <= ordinal <= len(slots):
        raw = slots[ordinal - 1]
        return SlotOfferRecord(
            doctor_id=int(raw["doctor_id"]),
            doctor_name=str(raw["doctor_name"]),
            start_utc=str(raw["start_utc"]),
            end_utc=str(raw["end_utc"]),
        )
    return None


def mark_outcome(session: Session, state: State) -> None:
    """Record a terminal outcome that has already been committed.

    Deliberately not a transition. The state machine governs conversation, and a
    conversation cannot veto a fact the database has already accepted: once an
    appointment row is cancelled, the session is in CANCELLED whatever the
    machine believed a moment earlier.
    """
    session.state = state.value


def touch(session: Session) -> None:
    session.turn_count += 1
