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
    SpokenFragment,
    StrictModel,
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


# --------------------------------------------------------------- responses


class DoctorOffer(StrictModel):
    ordinal: int
    name: str
    specialty: str


class SearchDoctorsResult(StrictModel):
    results: list[DoctorOffer]


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


class UniformFailure(StrictModel):
    """The only thing a denied caller ever sees (6.2)."""

    detail: str
