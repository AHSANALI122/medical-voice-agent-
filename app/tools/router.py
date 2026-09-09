"""/tools/* endpoints (F3).

Thin by design. Each handler validates (Pydantic, already done), authorizes
(Authorizer, explicit and after validation), delegates to a service, and maps
the result to an explicit response model. No business rule is written here and
no ORM object is serialized.

There is no list endpoint at any privilege level (C-37).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.db.base import db_session
from app.schemas.tools import (
    AppendDigitsRequest,
    BookAppointmentRequest,
    BookAppointmentResult,
    CancelAppointmentRequest,
    CancelAppointmentResult,
    ClearDigitsRequest,
    CreateSessionRequest,
    CreateSessionResult,
    DigitBufferResult,
    DoctorOffer,
    GetAvailableSlotsRequest,
    GetAvailableSlotsResult,
    SearchDoctorsRequest,
    SearchDoctorsResult,
    SlotOffer,
)
from app.security.authorization import Authorizer, forbidden, get_authorizer
from app.security.normalize import normalize_name
from app.security.request_auth import AuthenticatedChannel, require_signed_request
from app.services import booking, digits, directory, sessions
from app.services.slots import available_slots
from app.services.state_machine import State

router = APIRouter(prefix="/tools", tags=["tools"])

DISCLOSURE = (
    "This call is recorded, and you're speaking with an AI assistant. "
    "I can book or cancel an appointment. I can't give medical advice."
)


def _spoken(dt_local: datetime) -> str:
    """A slot as a person would say it. Presentation only."""
    return dt_local.strftime("%A the %d at %I:%M %p").replace(" 0", " ")


def _local(dt_utc: datetime) -> datetime:
    return dt_utc.astimezone(get_settings().clinic_tz)


@router.post("/create_session", response_model=CreateSessionResult)
def create_session(
    payload: CreateSessionRequest,
    channel: AuthenticatedChannel = Depends(require_signed_request),
    db: OrmSession = Depends(db_session),
) -> CreateSessionResult:
    session = sessions.create_session(db, channel=channel.name, consent=payload.consent_given)
    db.commit()
    return CreateSessionResult(
        session_id=session.id, state=session.state, disclosure=DISCLOSURE
    )


@router.post("/search_doctors", response_model=SearchDoctorsResult)
def search_doctors(
    payload: SearchDoctorsRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> SearchDoctorsResult:
    session = authz.session(payload.session_id)

    entries = directory.search(
        specialty=payload.specialty, doctor_query=payload.doctor_query
    )
    # Public directory, but still bounded: an unbounded roster is a scrape.
    entries = entries[:8]

    sessions.record_doctor_offers(session, [e.doctor_id for e in entries])
    sessions.touch(session)
    authz.db.commit()

    return SearchDoctorsResult(
        results=[
            DoctorOffer(ordinal=i, name=e.full_name, specialty=e.specialty)
            for i, e in enumerate(entries, start=1)
        ]
    )


@router.post("/get_available_slots", response_model=GetAvailableSlotsResult)
def get_available_slots(
    payload: GetAvailableSlotsRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> GetAvailableSlotsResult:
    session = authz.session(payload.session_id)

    doctor_id = sessions.resolve_doctor_ordinal(session, payload.doctor_ordinal)
    if doctor_id is None:
        # An ordinal this session was never offered. Not a validation problem:
        # the shape is fine, the caller just has no standing to name that row.
        raise forbidden()

    entry = next((e for e in directory.whitelist() if e.doctor_id == doctor_id), None)
    if entry is None:
        raise forbidden()

    found = available_slots(authz.db, doctor_id=doctor_id, on_date=payload.on_date)

    sessions.record_slot_offers(
        session,
        [
            sessions.SlotOfferRecord(
                doctor_id=s.doctor_id,
                doctor_name=entry.full_name,
                start_utc=s.start_utc.isoformat(),
                end_utc=s.end_utc.isoformat(),
            )
            for s in found
        ],
    )
    sessions.touch(session)
    authz.db.commit()

    return GetAvailableSlotsResult(
        slots=[
            SlotOffer(
                ordinal=i,
                doctor_name=entry.full_name,
                starts_at_local=_local(s.start_utc).isoformat(),
                spoken=_spoken(_local(s.start_utc)),
            )
            for i, s in enumerate(found, start=1)
        ]
    )


@router.post("/book_appointment", response_model=BookAppointmentResult)
def book_appointment(
    payload: BookAppointmentRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> BookAppointmentResult:
    session = authz.session(payload.session_id)

    offer = sessions.resolve_slot_ordinal(session, payload.slot_ordinal)
    if offer is None:
        raise forbidden()

    try:
        result = booking.book(
            authz.db,
            doctor_id=offer.doctor_id,
            start_utc=datetime.fromisoformat(offer.start_utc),
            end_utc=datetime.fromisoformat(offer.end_utc),
            patient_name=payload.patient_name,
            idempotency_key=f"{authz.channel.name}:{payload.idempotency_key}",
            session_id=session.id,
            channel=authz.channel.name,
        )
    except booking.SlotTaken:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That time was just taken. Let me offer you another.",
        ) from None

    sessions.mark_outcome(session, State.BOOKED)
    sessions.touch(session)
    authz.db.commit()

    local = _local(result.start_utc)
    return BookAppointmentResult(
        confirmed=True,
        doctor_name=result.doctor_name,
        starts_at_local=local.isoformat(),
        spoken=_spoken(local),
        reference=result.reference,
    )


@router.post("/append_reference_digits", response_model=DigitBufferResult)
def append_reference_digits(
    payload: AppendDigitsRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> DigitBufferResult:
    """The server-side buffer from section 6.4.

    Fragments append across turns, so a VAD cut in the middle of a code costs
    the caller nothing.
    """
    session = authz.session(payload.session_id)

    state = digits.append_fragment(
        session.digit_buffer, payload.fragment, retries=session.digit_retries
    )
    session.digit_buffer = state.digits
    session.digit_retries = state.retries
    session.digits_confirmed = False
    sessions.touch(session)
    authz.db.commit()

    return DigitBufferResult(
        digits_collected=len(state.digits),
        ready=state.ready,
        readback=state.readback,
        retries_exhausted=digits.retries_exhausted(state.retries),
    )


@router.post("/clear_reference_digits", response_model=DigitBufferResult)
def clear_reference_digits(
    payload: ClearDigitsRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> DigitBufferResult:
    session = authz.session(payload.session_id)

    state = digits.clear_buffer(session.digit_retries)
    session.digit_buffer = state.digits
    session.digit_retries = state.retries
    session.digits_confirmed = False
    sessions.touch(session)
    authz.db.commit()

    return DigitBufferResult(
        digits_collected=0,
        ready=False,
        readback=None,
        retries_exhausted=digits.retries_exhausted(state.retries),
    )


@router.post("/cancel_appointment", response_model=CancelAppointmentResult)
def cancel_appointment(
    payload: CancelAppointmentRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> CancelAppointmentResult:
    """Name + date + reference, matched in one server-side step (5.2).

    Every denial is the same 403 with the same body: wrong name, wrong date,
    wrong reference, no such record, ambiguity, lockout. The caller cannot tell
    them apart, so the flow is not an existence oracle (C-32).
    """
    session = authz.session(payload.session_id)

    result = booking.cancel(
        authz.db,
        normalized_name=normalize_name(payload.patient_name),
        appointment_date=payload.appointment_date,
        reference=payload.reference,
        session_id=session.id,
        channel=authz.channel.name,
        client_ip=authz.channel.client_ip,
        now=datetime.now(timezone.utc),
    )

    if result is None:
        # Commit first: the denial audit row is part of this attempt, and an
        # attacker must not be able to discard their own trail by disconnecting.
        session.digit_buffer = ""
        session.digits_confirmed = False
        sessions.touch(session)
        authz.db.commit()
        raise forbidden()

    sessions.mark_outcome(session, State.CANCELLED)
    session.digit_buffer = ""
    session.digits_confirmed = False
    sessions.touch(session)
    authz.db.commit()

    local = _local(result.start_utc)
    return CancelAppointmentResult(
        confirmed=True,
        doctor_name=result.doctor_name,
        starts_at_local=local.isoformat(),
        spoken=_spoken(local),
    )
