"""Booking and cancellation services.

The application's free-slot check is advisory. The database's partial unique
index on (doctor_id, slot_start_utc) among active rows is what actually decides
the race (C-12): two callers offered the same slot at the same instant both pass
the check, and exactly one commits.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date as Date
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.models import (
    ACTION_BOOK,
    ACTION_CANCEL,
    DECISION_ALLOWED,
    DECISION_DENIED,
    REASON_ALREADY_CANCELLED,
    REASON_IDEMPOTENT_REPLAY,
    REASON_MATCH,
    REASON_SLOT_TAKEN,
    STATUS_ACTIVE,
    STATUS_CANCELLED,
    Appointment,
    Doctor,
    Patient,
)
from app.security.crypto import encrypt_field
from app.security.normalize import normalize_name
from app.security.reference import (
    issue_reference,
    match_cancellation_candidate,
)
from app.services import audit


class SlotTaken(Exception):
    """Lost the race. The caller is offered fresh slots, never an error."""


def scoped_idempotency_key(*, channel: str, session_id: str, client_key: str) -> str:
    """Namespace a client-supplied idempotency key (F15).

    The scoping is a security control, not tidiness. A replay of this key hands
    back the original booking reference in plaintext, which is the whole
    authority to cancel that appointment (section 5.2). The key itself arrives
    from the agent layer, and section 8 says to assume the model will eventually
    send attacker-chosen arguments — so the key's entropy cannot be the thing
    protecting the reference.

    Scoped to the session, it does not have to be. A session id is server-minted
    with `secrets`, bound to one channel, and expires in 15 minutes; a caller who
    can replay this key is a caller who already holds the session the reference
    was disclosed to. Guessing another caller's key now buys nothing, because the
    guesser's own session id is prepended to it.

    The channel stays in the key so the same session id could never be replayed
    across channels even if one were somehow leaked between them.
    """
    return f"{channel}:{session_id}:{client_key}"


@dataclass(frozen=True)
class BookingResult:
    appointment_id: int
    doctor_name: str
    start_utc: datetime
    reference: str
    replayed: bool


@dataclass(frozen=True)
class CancellationResult:
    doctor_name: str
    start_utc: datetime


def _find_or_create_patient(db: OrmSession, name: str) -> Patient:
    """Names collide legitimately; a shared normalized form is not the same
    person. A new row per booking keeps two Ahmed Khans distinct at the record
    level, and the reference is what tells them apart at cancellation (C-33).
    """
    ciphertext, nonce, key_id = encrypt_field(name)
    patient = Patient(
        name_enc=ciphertext,
        name_nonce=nonce,
        key_id=key_id,
        name_normalized=normalize_name(name),
    )
    db.add(patient)
    db.flush()
    return patient


def is_replay(db: OrmSession, idempotency_key: str) -> bool:
    """Has this exact scoped key already produced an appointment?

    Asked by the endpoint before it charges the daily booking budget. A replay
    creates no row and takes no slot, so gating it behind a cap that exists to
    protect slots refuses a caller who has not consumed anything — and refuses
    them at the worst possible moment, because the retry is how they recover a
    reference whose confirmation was lost on the wire.

    This opens no bypass. A key only answers True here once a row already exists
    under it, and creating that row is what cost the budget in the first place.
    """
    return (
        db.execute(
            select(Appointment.id)
            .where(Appointment.idempotency_key == idempotency_key)
            .limit(1)
        ).first()
        is not None
    )


def book(
    db: OrmSession,
    *,
    doctor_id: int,
    start_utc: datetime,
    end_utc: datetime,
    patient_name: str,
    idempotency_key: str,
    session_id: str,
    channel: str,
) -> BookingResult:
    """Create one appointment and issue its reference.

    F15: a repeat of the same idempotency key returns the original result and
    the original reference rather than a second appointment. The reference is
    re-issued from the replay cache, not from the database, because the database
    holds only its HMAC.
    """
    doctor = db.get(Doctor, doctor_id)
    if doctor is None or not doctor.active:
        raise SlotTaken()

    existing = db.execute(
        select(Appointment).where(Appointment.idempotency_key == idempotency_key)
    ).scalar_one_or_none()
    if existing is not None:
        cached = replay_reference(idempotency_key)
        if cached is None:
            # The row exists but the plaintext is gone, which is correct: the
            # reference is recoverable only inside the window it was issued in.
            raise SlotTaken()
        audit.record(
            db,
            action=ACTION_BOOK,
            decision=DECISION_ALLOWED,
            reason=REASON_IDEMPOTENT_REPLAY,
            session_id=session_id,
            channel=channel,
            target_appointment_id=existing.id,
        )
        doctor_name = db.get(Doctor, existing.doctor_id).full_name
        return BookingResult(
            appointment_id=existing.id,
            doctor_name=doctor_name,
            start_utc=existing.slot_start_utc,
            reference=cached,
            replayed=True,
        )

    patient = _find_or_create_patient(db, patient_name)
    reference, digest, key_id = issue_reference(db)

    appointment = Appointment(
        doctor_id=doctor_id,
        patient_id=patient.id,
        slot_start_utc=start_utc,
        slot_end_utc=end_utc,
        status=STATUS_ACTIVE,
        reference_hmac=digest,
        reference_key_id=key_id,
        idempotency_key=idempotency_key,
    )
    db.add(appointment)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        # The unique index refused it, which is the point: the slot was taken
        # between the offer and the commit.
        audit.record(
            db,
            action=ACTION_BOOK,
            decision=DECISION_DENIED,
            reason=REASON_SLOT_TAKEN,
            session_id=session_id,
            channel=channel,
        )
        db.commit()
        raise SlotTaken() from None

    audit.record(
        db,
        action=ACTION_BOOK,
        decision=DECISION_ALLOWED,
        reason=REASON_MATCH,
        session_id=session_id,
        channel=channel,
        target_appointment_id=appointment.id,
    )
    remember_reference(idempotency_key, reference)
    return BookingResult(
        appointment_id=appointment.id,
        doctor_name=doctor.full_name,
        start_utc=start_utc,
        reference=reference,
        replayed=False,
    )


def cancel(
    db: OrmSession,
    *,
    normalized_name: str,
    appointment_date: Date,
    reference: str,
    session_id: str,
    channel: str,
    client_ip: str,
    now: datetime | None = None,
) -> CancellationResult | None:
    """The whole cancellation path. Returns None on every denial.

    Exactly one audit row is written per attempt, allowed or denied, inside the
    mutation's transaction (C-28). The caller-facing outcome is identical for
    every denial reason; only the audit row knows which one it was.
    """
    now = now or datetime.now(timezone.utc)
    outcome = match_cancellation_candidate(
        db,
        normalized_name=normalized_name,
        appointment_date=appointment_date,
        reference=reference,
        client_ip=client_ip,
        now=now,
    )

    if not outcome.allowed:
        audit.record(
            db,
            action=ACTION_CANCEL,
            decision=DECISION_DENIED,
            reason=outcome.reason,
            session_id=session_id,
            channel=channel,
            target_appointment_id=outcome.appointment_id,
        )
        return None

    appointment = db.get(Appointment, outcome.appointment_id)
    if appointment is None or appointment.status != STATUS_ACTIVE:
        # Cancelling an already-cancelled appointment is idempotent: the caller
        # sees the same denial, and the audit row records why.
        audit.record(
            db,
            action=ACTION_CANCEL,
            decision=DECISION_DENIED,
            reason=REASON_ALREADY_CANCELLED,
            session_id=session_id,
            channel=channel,
            target_appointment_id=outcome.appointment_id,
        )
        return None

    appointment.status = STATUS_CANCELLED
    appointment.cancelled_at = now

    audit.record(
        db,
        action=ACTION_CANCEL,
        decision=DECISION_ALLOWED,
        reason=REASON_MATCH,
        session_id=session_id,
        channel=channel,
        target_appointment_id=appointment.id,
    )

    doctor = db.get(Doctor, appointment.doctor_id)
    return CancellationResult(
        doctor_name=doctor.full_name if doctor else "your doctor",
        start_utc=appointment.slot_start_utc,
    )


# --------------------------------------------------------------------------
# Reference readback (section 5.1).
#
# The reference must be speakable once more if the caller asks within the same
# call, and it must never be written to the database in plaintext. So it lives
# in process memory for the length of a session, and nowhere else.
# --------------------------------------------------------------------------

_readback: dict[str, tuple[str, datetime]] = {}


def remember_reference(idempotency_key: str, reference: str) -> None:
    settings = get_settings()
    expires = datetime.now(timezone.utc).timestamp() + settings.session_ttl_minutes * 60
    _readback[idempotency_key] = (
        reference,
        datetime.fromtimestamp(expires, tz=timezone.utc),
    )
    _prune_readback()


def replay_reference(idempotency_key: str) -> str | None:
    _prune_readback()
    entry = _readback.get(idempotency_key)
    return entry[0] if entry else None


def forget_references() -> None:
    _readback.clear()


def _prune_readback() -> None:
    now = datetime.now(timezone.utc)
    for key in [k for k, (_, exp) in _readback.items() if exp <= now]:
        del _readback[key]
