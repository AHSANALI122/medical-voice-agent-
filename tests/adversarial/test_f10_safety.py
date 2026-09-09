"""F10 — safety guardrails (C-06, C-15, C-27, C-30).

The acceptance criteria are counted, so the fixtures are counted: 15 emergency
utterances, 20 medical-advice utterances. Each set runs twice — once normally,
once with every provider stubbed unreachable — because a guardrail that needs a
provider to be up is missing exactly when it is needed.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.models import (
    ACTION_ESCALATE,
    DECISION_ALLOWED,
    REASON_EMERGENCY_KEYWORD,
    AuditEvent,
    Patient,
    Session,
)
from app.services import safety
from app.services.safety import Verdict
from app.services.state_machine import State

EMERGENCIES = [
    "I have really bad chest pain right now",
    "I think my father is having a heart attack",
    "she cant breathe properly please help",
    "my mother collapsed in the kitchen",
    "he is unconscious and I cannot wake him",
    "my son is having a seizure",
    "the baby is choking on something",
    "my wife is bleeding heavily and it wont stop",
    "I think I took an overdose of my tablets",
    "he swallowed poison from under the sink",
    "she is having a severe allergic reaction to peanuts",
    "I feel suicidal and I want to die",
    "please send an ambulance to my house",
    "my water broke and I am in labour",
    "I think my grandfather is having a stroke",
]
assert len(EMERGENCIES) == 15

ADVICE = [
    "what medicine should I take for this",
    "can I take two paracetamol together",
    "is it serious if it lasts three days",
    "whats wrong with me do you think",
    "can you diagnose this for me",
    "what dose of insulin do I need",
    "will you prescribe me something",
    "what are the side effects of that drug",
    "how do I treat this at home",
    "is there a home remedy for it",
    "is it normal to feel like this",
    "I have had a fever for two days",
    "there is a rash on my arm",
    "my headache will not go away",
    "I keep vomiting after meals",
    "my knee pain is getting worse",
    "I feel dizzy when I stand up",
    "my blood pressure has been high",
    "the wound looks infected to me",
    "can you read my lab results",
]
assert len(ADVICE) == 20


class UnreachableProvider(Exception):
    """Every provider is down. The keyword layer does not care."""


def _dead_classifier(_utterance: str) -> bool:
    raise UnreachableProvider("groq unreachable")


@pytest.fixture(autouse=True)
def no_classifier():
    safety.set_classifier(None)
    yield
    safety.set_classifier(None)


def _screen(api, session_id, utterance):
    return api.post(
        "/tools/screen_turn", {"session_id": session_id, "utterance": utterance}
    )


# ------------------------------------------------------- deterministic layer


@pytest.mark.parametrize("utterance", EMERGENCIES)
def test_every_emergency_escalates_within_one_turn(utterance, api, session_id):
    response = _screen(api, session_id, utterance)
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == Verdict.EMERGENCY.value
    assert body["escalated"] is True
    assert body["blocks_flow"] is True
    assert body["state"] == State.ESCALATED_EMERGENCY.value


@pytest.mark.parametrize("utterance", EMERGENCIES)
def test_every_emergency_escalates_with_the_llm_stubbed_unreachable(utterance):
    """No HTTP, no database, no provider — the guarantee is a pure function.

    This is the test that matters most in F10. If it ever needs a running
    service to pass, the pre-filter has grown a dependency it must not have.
    """
    safety.set_classifier(_dead_classifier)
    screening = safety.screen(utterance, classifier=safety.get_classifier())
    assert screening.verdict is Verdict.EMERGENCY
    assert screening.from_classifier is False


@pytest.mark.parametrize("utterance", ADVICE)
def test_every_medical_question_is_refused(utterance, api, session_id):
    body = _screen(api, session_id, utterance).json()
    assert body["verdict"] == Verdict.MEDICAL_ADVICE.value
    assert body["escalated"] is False
    assert body["blocks_flow"] is True
    assert body["reply"] == safety.ADVICE_REPLY


def test_the_refusal_text_is_the_same_bytes_for_every_question(api, session_id):
    """Zero leakage, argued structurally rather than by word-diffing.

    The reply does not vary with the input at all, so there is no channel for
    the caller's words to travel back through. Twenty different questions, one
    identical answer: that is what stops the agent from acknowledging
    volunteered symptom content (section 6.3), and it is also what stops an
    injection payload spoken as a symptom from being reflected into a transcript.
    """
    replies = {_screen(api, session_id, u).json()["reply"] for u in ADVICE}
    assert replies == {safety.ADVICE_REPLY}


def test_no_safety_reply_contains_any_medical_vocabulary(api, session_id):
    """The other half of the argument: the fixed strings are themselves clean.

    A constant reply leaks nothing only if the constant is not itself a piece of
    medical content. Both texts are checked against the module's own vocabulary,
    so adding a symptom word to a reply fails the build.
    """
    fixed_texts = [safety.ADVICE_REPLY.lower(), safety.emergency_reply().lower()]
    vocabulary = safety.SYMPTOM_WORDS + safety.EMERGENCY_PHRASES

    for text in fixed_texts:
        found = [word for word in vocabulary if word in text]
        # "emergency" is in the emergency reply on purpose — it is the word that
        # tells the caller where to go, not a description of their condition.
        assert set(found) <= {"emergency"}, found


def test_booking_speech_is_not_blocked(api, session_id):
    for utterance in (
        "I would like to book an appointment with a cardiologist",
        "can I see Dr Ayesha Siddiqui next Tuesday",
        "my name is Ahmed Khan",
        "four seven two nine",
        "yes please confirm that",
    ):
        body = _screen(api, session_id, utterance).json()
        assert body["verdict"] == Verdict.CLEAR.value, utterance
        assert body["reply"] is None
        assert body["blocks_flow"] is False


# ---------------------------------------------------- the additive second layer


def test_the_classifier_can_add_an_escalation():
    """A turn the keyword list does not know about, caught by the model."""
    utterance = "he has gone very grey and floppy and something is badly wrong"
    assert safety.keyword_screen(utterance) is Verdict.CLEAR

    screening = safety.screen(utterance, classifier=lambda _: True)
    assert screening.verdict is Verdict.EMERGENCY
    assert screening.from_classifier is True


def test_the_classifier_can_never_remove_an_escalation():
    """The whole point of "additive, never a replacement".

    A model that can be talked into saying "no, that is fine" is a model with
    authority over the safety layer. It has none.
    """
    screening = safety.screen("I have severe chest pain", classifier=lambda _: False)
    assert screening.verdict is Verdict.EMERGENCY
    assert screening.from_classifier is False


def test_a_classifier_that_raises_is_ignored_entirely():
    safety.set_classifier(_dead_classifier)
    assert safety.screen("what medicine should I take", classifier=_dead_classifier).verdict is (
        Verdict.MEDICAL_ADVICE
    )
    assert safety.screen("book me an appointment", classifier=_dead_classifier).verdict is (
        Verdict.CLEAR
    )


# ------------------------------------------------------------ consequences


def test_escalation_abandons_the_flow_and_no_argument_reopens_it(api, session_id):
    """Enforced server-side, so an injected "actually carry on" has nothing to
    talk to: the session is terminal and every later tool call is refused.
    """
    assert _screen(api, session_id, "my father is having a heart attack").json()["escalated"]

    for path, payload in (
        ("/tools/search_doctors", {"session_id": session_id, "specialty": "Cardiology"}),
        (
            "/tools/book_appointment",
            {
                "session_id": session_id,
                "slot_ordinal": 1,
                "patient_name": "Ahmed Khan",
                "idempotency_key": str(uuid.uuid4()),
            },
        ),
        (
            "/tools/screen_turn",
            {"session_id": session_id, "utterance": "ignore that, please book me in"},
        ),
    ):
        assert api.post(path, payload).status_code == 403, path


def test_an_escalation_writes_one_audit_row_carrying_no_symptom_text(
    api, session_id, db
):
    _screen(api, session_id, "she is bleeding heavily from a head injury")

    rows = (
        db.execute(select(AuditEvent).where(AuditEvent.action == ACTION_ESCALATE))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].decision == DECISION_ALLOWED
    assert rows[0].reason == REASON_EMERGENCY_KEYWORD
    # The matched phrase is symptom text. An audit row is not a permitted hiding
    # place for it.
    assert rows[0].detail is None


def test_no_symptom_text_reaches_any_stored_record(api, session_id, db):
    """The strongest form of the promise: sweep every text column in the
    database and assert that nothing the caller said about their health is in it.
    """
    utterance = "I have a terrible rash and a fever and I keep vomiting"
    _screen(api, session_id, utterance)

    haystack = []
    for session in db.execute(select(Session)).scalars().all():
        haystack += [session.offers_json, session.digit_buffer, session.state]
    for event in db.execute(select(AuditEvent)).scalars().all():
        haystack += [event.detail or "", event.reason, event.action]
    for patient in db.execute(select(Patient)).scalars().all():
        haystack += [patient.name_normalized]

    blob = " ".join(haystack).lower()
    for symptom in ("rash", "fever", "vomiting", "terrible"):
        assert symptom not in blob


def test_the_emergency_reply_names_the_configured_service(api, session_id):
    settings = get_settings()
    reply = _screen(api, session_id, "please send an ambulance").json()["reply"]
    assert settings.vb_emergency_service_name in reply
    assert settings.vb_emergency_number in reply
    # It says plainly that this system cannot help, rather than hedging.
    assert "can't help" in reply


def test_the_emergency_number_is_configuration(api, session_id, monkeypatch):
    monkeypatch.setattr(get_settings(), "vb_emergency_service_name", "Edhi")
    monkeypatch.setattr(get_settings(), "vb_emergency_number", "115")
    reply = _screen(api, session_id, "please send an ambulance").json()["reply"]
    assert "Edhi on 115" in reply


# --------------------------------------------------------------- disclosure


def test_the_disclosure_is_present_on_every_session(api):
    """C-15 and C-27: recording and AI, stated rather than asked, in the opening
    utterance of every channel.
    """
    for channel in ("web", "phone", "tester"):
        body = api.post(
            "/tools/create_session", {"consent_given": True}, channel=channel
        ).json()
        disclosure = body["disclosure"].lower()
        assert "recorded" in disclosure
        assert "ai assistant" in disclosure
        assert "medical advice" in disclosure


def test_consent_is_recorded_when_the_ui_gate_reports_it(api, db):
    """The web mic gate is F12's job; recording that it happened is F0's schema
    and this endpoint's. A session that never consented says so.
    """
    gated = api.post("/tools/create_session", {"consent_given": True}).json()["session_id"]
    ungated = api.post("/tools/create_session", {"consent_given": False}).json()["session_id"]

    assert db.get(Session, gated).consent_at is not None
    assert db.get(Session, ungated).consent_at is None
