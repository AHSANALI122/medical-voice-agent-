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
from app.models import (
    ACTION_ESCALATE,
    ACTION_RATE_LIMIT,
    DECISION_ALLOWED,
    DECISION_DENIED,
    REASON_EMERGENCY_KEYWORD,
    REASON_RATE_LIMITED,
)
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
    ResolveDateRequest,
    ResolveDateResult,
    ScreenTurnRequest,
    ScreenTurnResult,
    SearchDoctorsRequest,
    SearchDoctorsResult,
    SlotOffer,
)
from app.security import rate_limit
from app.security.authorization import Authorizer, forbidden, get_authorizer
from app.security.normalize import normalize_name
from app.security.request_auth import AuthenticatedChannel, require_signed_request
from app.services import audit, booking, dates, digits, directory, safety, sessions
from app.services.slots import available_slots
from app.services.state_machine import State

router = APIRouter(prefix="/tools", tags=["tools"])

DISCLOSURE = (
    "This call is recorded, and you're speaking with an AI assistant. "
    "I can book or cancel an appointment. I can't give medical advice."
)


def _too_many_requests() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=rate_limit.RATE_LIMITED_TEXT,
    )


def _refuse_over_budget(
    db: OrmSession,
    exc: rate_limit.RateLimited,
    *,
    channel: str,
    session_id: str | None = None,
) -> HTTPException:
    """Record the refusal, then hand back the one uniform 429.

    The scope goes in the audit row and never in the response: an attacker who
    learns which budget they tripped learns which one to work around. The row is
    committed here because raising aborts the request and an abuser must not be
    able to discard their own trail by being refused.

    Only the first refusal in a budget's window is written. A client that ignores
    a 429 and keeps calling would otherwise write one audit row per request,
    which turns a rate limit into a way of filling a disk. The bucket's count
    still records every attempt.
    """
    if exc.first_refusal:
        audit.record(
            db,
            action=ACTION_RATE_LIMIT,
            decision=DECISION_DENIED,
            reason=REASON_RATE_LIMITED,
            session_id=session_id,
            channel=channel,
            detail=exc.scope,
        )
    db.commit()
    return _too_many_requests()


def _spoken(dt_local: datetime) -> str:
    """A slot as a person would say it. Presentation only.

    Shares its day form with the F7 readback rather than rolling its own: one
    readback format for the whole system, so a slot offer and a date
    confirmation cannot describe the same day two different ways.
    """
    clock = dt_local.strftime("%I:%M %p").lstrip("0")
    return f"{dates.spoken_day(dt_local.date())} at {clock}"


def _local(dt_utc: datetime) -> datetime:
    return dt_utc.astimezone(get_settings().clinic_tz)


@router.post("/create_session", response_model=CreateSessionResult)
def create_session(
    payload: CreateSessionRequest,
    channel: AuthenticatedChannel = Depends(require_signed_request),
    db: OrmSession = Depends(db_session),
) -> CreateSessionResult:
    # F8 — the call budget is charged here rather than per turn, because a call
    # is the unit the caps in C-07 and C-14 are written about. Both budgets are
    # keyed on values that survive a reconnect: a source address and a signed
    # platform call id, never session_id (C-23).
    try:
        rate_limit.require_call_budget(
            db, client_ip=channel.client_ip, call_id=channel.call_id
        )
    except rate_limit.RateLimited as exc:
        raise _refuse_over_budget(db, exc, channel=channel.name) from None

    session = sessions.create_session(db, channel=channel.name, consent=payload.consent_given)
    rate_limit.consume_call_budget(
        db, client_ip=channel.client_ip, call_id=channel.call_id
    )
    db.commit()
    return CreateSessionResult(
        session_id=session.id, state=session.state, disclosure=DISCLOSURE
    )


@router.post("/resolve_date", response_model=ResolveDateResult)
def resolve_date(
    payload: ResolveDateRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> ResolveDateResult:
    """Resolve a spoken date against the clinic calendar (F7).

    Server-side, like everything else the model would otherwise be trusted to
    get right. "Today" here is today in the clinic's timezone — not the caller's
    and not the model's, which has no reliable idea what day it is.

    This endpoint discloses nothing: it maps text to a date and knows nothing
    about whether anybody has an appointment on it.
    """
    session = authz.session(payload.session_id)

    resolution = dates.parse_spoken_date(
        payload.phrase, allow_past=payload.for_cancellation
    )

    sessions.touch(session)
    authz.db.commit()

    return ResolveDateResult(
        outcome=resolution.outcome.value,
        resolved_date=resolution.value.isoformat() if resolution.value else None,
        spoken=resolution.spoken,
        clarification=resolution.clarification,
    )


@router.post("/screen_turn", response_model=ScreenTurnResult)
def screen_turn(
    payload: ScreenTurnRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> ScreenTurnResult:
    """The F10 pre-filter. Every turn, before the state machine, every channel.

    Deliberately server-side rather than a rule in the agent prompt: a guardrail
    the model is asked to honour is a guardrail an injected utterance can argue
    with. This one is a function call whose result the agent has no vote on.

    The utterance dies here. It is not written to the session, not written to the
    audit row, not logged, and not echoed in the response — the emergency and
    redirect texts are fixed server-side strings. There is no reason-for-visit
    field in this system and this endpoint is where that promise is easiest to
    break (section 6.3, C-09).
    """
    session = authz.session(payload.session_id)

    screening = safety.screen(payload.utterance, classifier=safety.get_classifier())

    if screening.escalated:
        sessions.mark_outcome(session, State.ESCALATED_EMERGENCY)
        audit.record(
            authz.db,
            action=ACTION_ESCALATE,
            decision=DECISION_ALLOWED,
            reason=REASON_EMERGENCY_KEYWORD,
            session_id=session.id,
            channel=authz.channel.name,
            # No detail: the matched phrase is symptom text, and an audit row is
            # not a permitted hiding place for it.
            detail=None,
        )

    sessions.touch(session)
    authz.db.commit()

    return ScreenTurnResult(
        verdict=screening.verdict.value,
        reply=screening.reply,
        blocks_flow=screening.blocks_flow,
        escalated=screening.escalated,
        state=session.state,
    )


@router.post("/search_doctors", response_model=SearchDoctorsResult)
def search_doctors(
    payload: SearchDoctorsRequest,
    authz: Authorizer = Depends(get_authorizer),
) -> SearchDoctorsResult:
    session = authz.session(payload.session_id)

    # F6 — resolution happens in the whitelist, in memory. Caller text never
    # reaches SQL, so an injection payload spoken as a doctor's name resolves to
    # nothing rather than erroring or querying (C-11, C-35).
    if payload.doctor_query:
        resolution = directory.resolve_doctor(payload.doctor_query)
        entries = list(resolution.candidates)
        outcome = resolution.outcome.value
    elif payload.specialty:
        entries = directory.resolve_specialty(payload.specialty)
        outcome = (
            directory.Outcome.NO_MATCH.value
            if not entries
            else directory.Outcome.RESOLVED.value
        )
    else:
        entries = directory.whitelist()
        outcome = directory.Outcome.RESOLVED.value

    # Public directory, but still bounded: an unbounded roster is a scrape.
    entries = entries[:8]

    sessions.record_doctor_offers(session, [e.doctor_id for e in entries])
    sessions.touch(session)
    authz.db.commit()

    return SearchDoctorsResult(
        results=[
            DoctorOffer(ordinal=i, name=e.full_name, specialty=e.specialty)
            for i, e in enumerate(entries, start=1)
        ],
        resolution=outcome,
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

    normalized = normalize_name(payload.patient_name)
    try:
        rate_limit.require_booking_budget(authz.db, normalized_name=normalized)
    except rate_limit.RateLimited as exc:
        raise _refuse_over_budget(
            authz.db, exc, channel=authz.channel.name, session_id=session.id
        ) from None

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

    if not result.replayed:
        # Charged only once a row exists, and never on an idempotent replay:
        # the cap protects booked slots, and a retry of a call that already
        # booked one has not consumed a second (F15).
        rate_limit.consume_booking_budget(authz.db, normalized_name=normalized)

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
