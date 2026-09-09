"""Safety guardrails (F10 — C-06, C-15, C-27, C-30).

The emergency interrupt is a **pre-filter**, not a prompt instruction. It runs
before the state machine, on every turn, in pure Python, with no provider call
anywhere in its path. That is the whole design: a caller having a heart attack
must be redirected even when Groq is down, Deepgram is rate-limited and the LLM
is answering in confident nonsense. A guardrail that needs a provider to be up is
a guardrail that is missing exactly when it is needed (C-30).

The LLM classifier is an **additive second layer**. It can add an escalation the
keyword layer missed. It can never remove one, and the keyword verdict stands
untouched when the classifier is slow, unreachable, or lying. A model that can
talk the system out of escalating is a model with authority, which this project
does not give it.

Two things this module deliberately does not do:

**It never echoes the caller.** Every reply is a fixed server-side string. Not
one character of the utterance reaches the response, so an injection payload
spoken as a symptom cannot be reflected back into the transcript, and volunteered
symptom content is never acknowledged (section 6.3).

**It never stores the utterance.** Nothing here writes, logs, or returns the text
it screens. There is no reason-for-visit field in this system, and this function
— which is the one place symptom text reliably arrives — is where that promise is
easiest to break and therefore worth stating.

Accepted false-positive posture, stated rather than hidden: the keyword layer
matches "chest pain" in "my father had chest pain last year" and escalates. That
is the correct direction to be wrong in, and it is not the model's call to trade
away, which is why the classifier is additive-only.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from app.config import get_settings

log = logging.getLogger("voicebook.safety")

_PUNCTUATION = re.compile(r"[^a-z0-9]+")


class Verdict(str, Enum):
    CLEAR = "clear"
    MEDICAL_ADVICE = "medical_advice"
    EMERGENCY = "emergency"


# Phrases that end the conversation and route the caller to emergency services.
# Written as normalized word sequences and matched on word boundaries, so
# "breathe" does not fire on "breathing exercises class".
EMERGENCY_PHRASES: tuple[str, ...] = (
    "chest pain",
    "pain in my chest",
    "chest is hurting",
    "heart attack",
    "cardiac arrest",
    "stroke",
    "cant breathe",
    "cannot breathe",
    "can not breathe",
    "not breathing",
    "trouble breathing",
    "struggling to breathe",
    "unconscious",
    "passed out",
    "collapsed",
    "unresponsive",
    "seizure",
    "fitting",
    "convulsions",
    "choking",
    "bleeding heavily",
    "heavy bleeding",
    "severe bleeding",
    "wont stop bleeding",
    "coughing up blood",
    "overdose",
    "overdosed",
    "swallowed poison",
    "poisoned",
    "anaphylaxis",
    "anaphylactic",
    "severe allergic reaction",
    "suicidal",
    "kill myself",
    "end my life",
    "want to die",
    "emergency",
    "ambulance",
    "life threatening",
    "dying",
    "she is dying",
    "he is dying",
    "water broke",
    "in labour",
    "in labor",
    "severe burns",
    "head injury",
)

# Phrases that ask the agent to practise medicine. One warm redirect, no
# engagement with the content.
ADVICE_PHRASES: tuple[str, ...] = (
    "should i take",
    "can i take",
    "what medicine",
    "which medicine",
    "what medication",
    "what tablet",
    "what dose",
    "dosage",
    "prescribe",
    "prescription",
    "side effect",
    # Phrases are matched literally on word boundaries, so an inflected form is
    # a separate entry rather than a stemmer. A stemmer is a dependency and a
    # source of surprises; a longer list is neither.
    "side effects",
    "home remedies",
    "is it serious",
    "is this serious",
    "do i need surgery",
    "do i need a doctor",
    "whats wrong with me",
    "what is wrong with me",
    "diagnose",
    "diagnosis",
    "how do i treat",
    "how should i treat",
    "home remedy",
    "is it normal",
    "is that normal",
    "how long will it take to heal",
    "second opinion",
    "test results",
    "lab results",
)

# Symptom vocabulary. Its presence is enough on its own: the agent must not
# acknowledge volunteered symptom content, so the safe response to a caller
# describing one is the same warm redirect it gives to a direct question.
SYMPTOM_WORDS: tuple[str, ...] = (
    "fever",
    "rash",
    "headache",
    "migraine",
    "cough",
    "vomiting",
    "nausea",
    "diarrhea",
    "diarrhoea",
    "dizzy",
    "dizziness",
    "swelling",
    "swollen",
    "infection",
    "infected",
    "blood pressure",
    "diabetes",
    "diabetic",
    "asthma",
    "lump",
    "tumour",
    "tumor",
    "cancer",
    "depressed",
    "anxiety",
    "insomnia",
    "sore throat",
    "stomach ache",
    "back pain",
    "knee pain",
    "toothache",
    "itching",
    "allergy",
    "pregnant",
    "period pain",
    "symptoms",
    "hurts",
    "aching",
)


def normalize_utterance(raw: str) -> str:
    """Fold a spoken turn to a matching form: lowercase, punctuation to spaces.

    Returned only to the matcher. It is never stored and never logged.
    """
    return _PUNCTUATION.sub(" ", raw.lower()).strip()


def _contains(haystack: str, needle: str) -> bool:
    """Word-boundary containment on the normalized form."""
    return f" {needle} " in f" {haystack} "


@dataclass(frozen=True)
class Screening:
    verdict: Verdict
    reply: str | None
    # True when the classifier, not the keyword layer, produced the escalation.
    # Recorded so a silent regression in the deterministic layer is visible.
    from_classifier: bool = False

    @property
    def escalated(self) -> bool:
        return self.verdict is Verdict.EMERGENCY

    @property
    def blocks_flow(self) -> bool:
        return self.verdict is not Verdict.CLEAR


def emergency_reply() -> str:
    """The exact words the agent says. Not a prompt hint — the server supplies
    the string, because a safety message the model composes is a safety message
    the model can be talked out of.
    """
    settings = get_settings()
    return (
        "This sounds like a medical emergency, and I can't help with one — "
        "I only book and cancel appointments. Please hang up now and call "
        f"{settings.vb_emergency_service_name} on {settings.vb_emergency_number}, "
        "or go straight to your nearest emergency department."
    )


ADVICE_REPLY = (
    "I'm sorry — I'm not able to discuss medical matters at all, and I can't "
    "give advice. I can book you an appointment with a doctor who can. "
    "Would you like me to do that?"
)


# The optional second layer. A callable that takes an utterance and returns True
# if it believes this is an emergency. Anything else it returns, raises, or takes
# too long to say is discarded.
EmergencyClassifier = Callable[[str], bool]

_classifier: EmergencyClassifier | None = None


def set_classifier(classifier: EmergencyClassifier | None) -> None:
    global _classifier
    _classifier = classifier


def get_classifier() -> EmergencyClassifier | None:
    return _classifier


def keyword_screen(utterance: str) -> Verdict:
    """The deterministic layer. Pure function, no I/O, no provider, no model.

    This is the one that has to keep working when everything else is down, so it
    is the one with no dependencies.
    """
    text = normalize_utterance(utterance)
    if not text:
        return Verdict.CLEAR

    for phrase in EMERGENCY_PHRASES:
        if _contains(text, phrase):
            return Verdict.EMERGENCY

    for phrase in ADVICE_PHRASES:
        if _contains(text, phrase):
            return Verdict.MEDICAL_ADVICE

    for word in SYMPTOM_WORDS:
        if _contains(text, word):
            return Verdict.MEDICAL_ADVICE

    return Verdict.CLEAR


def screen(utterance: str, *, classifier: EmergencyClassifier | None = None) -> Screening:
    """Screen one turn. Keyword layer first, classifier only ever additive.

    The keyword verdict is computed before the classifier is consulted and is
    never revised downward by it. If the classifier raises — unreachable
    provider, timeout, malformed response — the failure is swallowed and the
    deterministic verdict stands. That is C-30 applied to safety: the unreliable
    component is designed so its failure is harmless.
    """
    verdict = keyword_screen(utterance)

    if verdict is Verdict.EMERGENCY:
        return Screening(Verdict.EMERGENCY, emergency_reply())

    if classifier is not None:
        try:
            if classifier(utterance) is True:
                return Screening(Verdict.EMERGENCY, emergency_reply(), from_classifier=True)
        except Exception:
            # Deliberately not `log.exception(utterance)`: the utterance is the
            # one thing that must not reach a log (C-09). Nothing about the
            # caller goes in this line.
            log.warning("safety_classifier_unavailable falling_back_to=keyword_layer")

    if verdict is Verdict.MEDICAL_ADVICE:
        return Screening(Verdict.MEDICAL_ADVICE, ADVICE_REPLY)

    return Screening(Verdict.CLEAR, None)
