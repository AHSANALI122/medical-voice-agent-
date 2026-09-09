"""Tool request and response models (F3, section 5.4).

Notice what no request model contains: a doctor id, a patient id, an appointment
id (C-04). Notice what no response model contains: an ORM object, an encrypted
column, an internal id, or more than one appointment (C-37).

The one exception to "no reference in a response body" is BookAppointmentResult,
which carries the reference exactly once, at the moment it is issued, because
the agent has to speak it (section 6.1 step 8). Nothing else ever returns it.
"""

from __future__ import annotations

from app.schemas.types import (
    AppointmentDate,
    BookingRef,
    IdempotencyKey,
    LookupDate,
    Ordinal,
    PatientName,
    SessionId,
    SpecialtyQuery,
    SpokenDate,
    SpokenFragment,
    StrictModel,
    Utterance,
)


# ---------------------------------------------------------------- requests


class SearchDoctorsRequest(StrictModel):
    session_id: SessionId
    specialty: SpecialtyQuery | None = None
    doctor_query: SpecialtyQuery | None = None


class GetAvailableSlotsRequest(StrictModel):
    session_id: SessionId
    doctor_ordinal: Ordinal
    on_date: AppointmentDate | None = None


class BookAppointmentRequest(StrictModel):
    session_id: SessionId
    slot_ordinal: Ordinal
    patient_name: PatientName
    idempotency_key: IdempotencyKey


class CancelAppointmentRequest(StrictModel):
    session_id: SessionId
    patient_name: PatientName
    appointment_date: LookupDate
    reference: BookingRef


class AppendDigitsRequest(StrictModel):
    session_id: SessionId
    fragment: SpokenFragment


class ClearDigitsRequest(StrictModel):
    session_id: SessionId


class CreateSessionRequest(StrictModel):
    consent_given: bool = False


class ResolveDateRequest(StrictModel):
    """A spoken date phrase, resolved against the clinic calendar (F7).

    `for_cancellation` widens the answer to include earlier today, because an
    appointment at nine this morning is an ordinary thing to want to cancel at
    ten. It grants no authority: the reference check is untouched by it.
    """

    session_id: SessionId
    phrase: SpokenDate
    for_cancellation: bool = False


class ScreenTurnRequest(StrictModel):
    """One turn of caller speech, screened and thrown away (F10).

    The utterance is the only free text in this API that may contain symptoms.
    It is never persisted, never logged, and never echoed in the response.
    """

    session_id: SessionId
    utterance: Utterance


# --------------------------------------------------------------- responses


class DoctorOffer(StrictModel):
    ordinal: int
    name: str
    specialty: str


class SearchDoctorsResult(StrictModel):
    """`resolution` tells the agent whether to proceed or to ask (F6).

    "ambiguous" means the server found more than one candidate and refused to
    pick. The agent's only correct move is to read the candidates back and let
    the caller choose — a doctor list is public, so naming them aloud is safe
    here in a way it never is for patients (C-33).
    """

    results: list[DoctorOffer]
    resolution: str


class SlotOffer(StrictModel):
    ordinal: int
    doctor_name: str
    starts_at_local: str
    spoken: str


class GetAvailableSlotsResult(StrictModel):
    slots: list[SlotOffer]


class BookAppointmentResult(StrictModel):
    confirmed: bool
    doctor_name: str
    starts_at_local: str
    spoken: str
    # Issued once, here, and never returned by any other endpoint.
    reference: str


class CancelAppointmentResult(StrictModel):
    confirmed: bool
    doctor_name: str
    starts_at_local: str
    spoken: str


class DigitBufferResult(StrictModel):
    digits_collected: int
    ready: bool
    readback: str | None
    retries_exhausted: bool


class CreateSessionResult(StrictModel):
    session_id: str
    state: str
    disclosure: str


class ResolveDateResult(StrictModel):
    """`spoken` is the readback, and it is the point.

    No parser settles what "next Tuesday" means. Reading the resolved date back
    to the caller catches a misparse in the same turn, which is cheaper than any
    amount of parser cleverness — the standing move of designing so an
    unreliable component's failures are harmless.
    """

    outcome: str
    resolved_date: str | None
    spoken: str | None
    clarification: str | None


class ScreenTurnResult(StrictModel):
    """`reply`, when present, is the exact text the agent must speak.

    The server supplies the words rather than a hint, because a safety message
    the model composes is a safety message the model can be talked out of. When
    `blocks_flow` is true the agent says `reply` and nothing else this turn.
    """

    verdict: str
    reply: str | None
    blocks_flow: bool
    escalated: bool
    state: str


class UniformFailure(StrictModel):
    """The only thing a denied caller ever sees (6.2)."""

    detail: str
