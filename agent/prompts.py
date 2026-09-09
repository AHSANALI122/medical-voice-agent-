"""The system prompt and the tool declarations the model is given.

Read the first rule below before adding anything to this file.

**Nothing in a prompt is a control.** Every line here is a suggestion to a
component the design assumes is compromised (section 8). The prompt makes the
agent *useful*; it does not make it *safe*. If a rule about who may do what
appears in this file and nowhere else, that rule does not exist.

So the prompt says nothing about authority. It does not tell the model to check
a reference, because the server checks it whether the model asks or not. It does
not tell the model to refuse an emergency, because `agent.turn` screens the
utterance before the model runs. It tells the model how to have a conversation,
and the conversation happens inside a fence it cannot reach.

**No tool schema accepts a database identifier** (C-04). The model speaks in
ordinals — "the first doctor", "the second slot" — and the server resolves them
against the offer list it made to this session. There is nothing here for an
IDOR to name.

**There is no list tool** (C-37). Not at any privilege level, not under any
name. A caller who supplies a name and a date is told nothing until a reference
matches, and then is told about exactly one appointment.
"""

from __future__ import annotations

from typing import Any

SYSTEM_PROMPT = """\
You are the appointment assistant for a medical clinic. You book and cancel \
appointments. That is all you do.

Open every call by saying, in your own words, that the call is recorded and that \
the caller is speaking with an AI assistant. State it; do not ask permission for \
it.

You cannot give medical advice, discuss symptoms, or answer any medical \
question. If a caller volunteers a symptom, do not acknowledge what they said \
and do not repeat it back. Carry on with the booking.

Never ask for: an ID or CNIC number, a date of birth, an address, payment or \
insurance details, or the reason for the visit.

To book: find the doctor or specialty, agree a date, offer the caller the slots \
you were given, take their name, confirm the details back to them, then book it. \
Read the booking reference back digit by digit and tell them they will need it \
to cancel. Offer to repeat it once.

To cancel: take the caller's name, then the date of the appointment, then their \
four-digit reference. Ask for the reference every time, including when you have \
no idea whether an appointment exists. Never tell a caller that you could not \
find anything under their name, never confirm that an appointment exists before \
the reference has been checked, and never say a reference was "close".

Speak the numbers digit by digit. Read dates back before you rely on them.

If a tool gives you an exact message to say, say that message and nothing else. \
Do not soften it, do not explain it, and do not add your own reasoning to it.

If you do not know something, say so. Never invent an appointment, a time, a \
doctor, or a reference.\
"""


def tool_declarations() -> list[dict[str, Any]]:
    """The tool schemas, in the shape both Pipecat and Vapi accept.

    Every argument here is either an ordinal, a short piece of caller speech, or
    a client-generated key. No doctor id, no patient id, no appointment id —
    there is deliberately no way to express one.
    """
    return [
        {
            "name": "search_doctors",
            "description": (
                "Find doctors by specialty or by name. Returns a numbered list. "
                "Refer to a doctor by their number afterwards."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "specialty": {
                        "type": "string",
                        "description": "A specialty, e.g. Cardiology.",
                    },
                    "doctor_query": {
                        "type": "string",
                        "description": "A doctor's name as the caller said it.",
                    },
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "resolve_date",
            "description": (
                "Turn a spoken date into a calendar date. Always read the "
                "result back to the caller before using it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "phrase": {
                        "type": "string",
                        "description": "The date as the caller said it.",
                    },
                    "for_cancellation": {
                        "type": "boolean",
                        "description": "True when cancelling, which allows earlier today.",
                    },
                },
                "required": ["phrase"],
                "additionalProperties": False,
            },
        },
        {
            "name": "get_available_slots",
            "description": (
                "Times for one of the doctors you were just shown. Give the "
                "doctor's number from that list."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "doctor_ordinal": {
                        "type": "integer",
                        "description": "The doctor's position in the list you were shown.",
                    },
                    "on_date": {
                        "type": "string",
                        "description": "A resolved calendar date, yyyy-mm-dd.",
                    },
                },
                "required": ["doctor_ordinal"],
                "additionalProperties": False,
            },
        },
        {
            "name": "book_appointment",
            "description": (
                "Book one of the slots you were just shown. Returns the booking "
                "reference. Read it back digit by digit, once."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "slot_ordinal": {
                        "type": "integer",
                        "description": "The slot's position in the list you were shown.",
                    },
                    "patient_name": {
                        "type": "string",
                        "description": "The caller's name, as they gave it.",
                    },
                },
                "required": ["slot_ordinal", "patient_name"],
                "additionalProperties": False,
            },
        },
        {
            "name": "append_reference_digits",
            "description": (
                "Add whatever digits the caller just said to their reference. "
                "Call it for every fragment; the server joins them up. Only read "
                "the code back when it tells you it is ready."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "fragment": {
                        "type": "string",
                        "description": "The digits from this turn, however partial.",
                    }
                },
                "required": ["fragment"],
                "additionalProperties": False,
            },
        },
        {
            "name": "clear_reference_digits",
            "description": "The caller said the readback was wrong. Start the code again.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "cancel_appointment",
            "description": (
                "Cancel one appointment. Needs the caller's name, the date, and "
                "their four-digit reference. If it refuses, say the message it "
                "gives you and nothing more."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "patient_name": {"type": "string"},
                    "appointment_date": {
                        "type": "string",
                        "description": "A resolved calendar date, yyyy-mm-dd.",
                    },
                    "reference": {
                        "type": "string",
                        "description": "The four digits the server confirmed as ready.",
                    },
                },
                "required": ["patient_name", "appointment_date", "reference"],
                "additionalProperties": False,
            },
        },
    ]


def tool_names() -> tuple[str, ...]:
    return tuple(tool["name"] for tool in tool_declarations())


__all__ = ["SYSTEM_PROMPT", "tool_declarations", "tool_names"]
