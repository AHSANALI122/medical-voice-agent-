"""C-32 — the cancel flow must not tell anyone whether a person has an
appointment.

The attack: phone in, say "Ahmed Khan, Tuesday", and read the difference between
"I can't find that" and "and your reference?". Answering honestly discloses that
a named person has a medical appointment. So the server answers identically, in
the same words and in the same time, whether or not the record exists.
"""

from __future__ import annotations

import itertools
import time
from datetime import date, timedelta
from statistics import median

import pytest

from app.db import base as db_base
from app.security.normalize import normalize_name
from app.security.reference import match_cancellation_candidate


# Each sample uses a fresh source address so the lockout does not kick in
# partway through and change what is being measured.
_ip_counter = itertools.count()


def _cancel(api, session_id, *, name, day, reference):
    return api.post(
        "/tools/cancel_appointment",
        {
            "session_id": session_id,
            "patient_name": name,
            "appointment_date": day,
            "reference": reference,
        },
    )


def test_wrong_reference_and_nonexistent_name_are_word_for_word_identical(
    api, session_id, booked
):
    record = booked(name="Ahmed Khan")

    wrong_reference = _cancel(
        api, session_id, name="Ahmed Khan", day=record["date"], reference="0000"
    )
    no_such_person = _cancel(
        api, session_id, name="Zulfiqar Noman", day=record["date"], reference="0000"
    )

    assert wrong_reference.status_code == no_such_person.status_code == 403
    assert wrong_reference.json() == no_such_person.json()


def test_wrong_date_is_also_indistinguishable(api, session_id, booked):
    record = booked(name="Ahmed Khan")
    other_day = (date.fromisoformat(record["date"]) + timedelta(days=1)).isoformat()

    wrong_date = _cancel(
        api, session_id, name="Ahmed Khan", day=other_day, reference=record["reference"]
    )
    no_such_person = _cancel(
        api, session_id, name="Zulfiqar Noman", day=other_day, reference="0000"
    )
    assert wrong_date.status_code == no_such_person.status_code == 403
    assert wrong_date.json() == no_such_person.json()


def test_failure_text_never_names_the_field_that_failed(api, session_id, booked):
    record = booked(name="Ahmed Khan")
    detail = _cancel(
        api, session_id, name="Ahmed Khan", day=record["date"], reference="0000"
    ).json()["detail"]

    lowered = detail.lower()
    for leak in ("reference", "name", "date", "not found", "no appointment", "incorrect"):
        assert leak not in lowered, f"failure text leaks {leak!r}: {detail!r}"


@pytest.mark.slow
def test_timing_of_no_match_and_wrong_reference_differ_by_under_20ms(db, booked, api):
    """F5 acceptance, measured at the matcher rather than through HTTP, so the
    number reflects the code under test and not the test client's overhead.
    """
    record = booked(name="Ahmed Khan")
    day = date.fromisoformat(record["date"])

    def sample(name: str, reference: str) -> float:
        session = db_base.get_sessionmaker()()
        try:
            start = time.perf_counter()
            match_cancellation_candidate(
                session,
                normalized_name=normalize_name(name),
                appointment_date=day,
                reference=reference,
                client_ip=f"203.0.113.{next(_ip_counter) % 250 + 1}",
            )
            session.rollback()
            return (time.perf_counter() - start) * 1000
        finally:
            session.close()

    # Warm the query plans and the connection before anything is recorded.
    for _ in range(30):
        sample("Ahmed Khan", "0000")
        sample("Zulfiqar Noman", "4729")

    # Interleaved on purpose. Timing the two arms in separate batches lets
    # machine-level drift land entirely on whichever runs second, which reads as
    # a leak that is not there — measured that way the gap looked like 60ms.
    wrong_reference: list[float] = []
    no_such_name: list[float] = []
    for _ in range(100):
        wrong_reference.append(sample("Ahmed Khan", "0000"))
        no_such_name.append(sample("Zulfiqar Noman", "4729"))

    assert abs(median(wrong_reference) - median(no_such_name)) < 20.0
    assert abs(sorted(wrong_reference)[94] - sorted(no_such_name)[94]) < 20.0
