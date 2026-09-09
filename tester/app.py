"""VoiceBook text tester (F9, C-13).

The whole flow — book and cancel — in text, so the authority check can be
debugged without a microphone in the way. Spec §10: perfect everything in text
before adding audio, because debugging a reference match through STT wastes
hours.

Every button here does exactly what the voice agent does: one signed HTTP call to
`/tools/*` on the `tester` channel. There is no shortcut, no test-only endpoint,
and no way to cancel without the reference. The panel on the right shows what
that cost — each call, its arguments, its status, its latency, and the audit rows
it produced.

Run it with:

    uv run streamlit run tester/app.py
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

# Streamlit runs this file as a script, not as a module, so `sys.path[0]` is
# `tester/` rather than the repository root and `import tester.audit` fails.
# Putting the root on the path is what makes the sibling imports below resolve.
#
# It does not weaken the trust boundary. That boundary is enforced by
# `scripts/check_import_boundary.py`, which parses the AST of every file under
# `tester/` and `agent/` and fails the build on an `app.services`, `app.db`,
# `app.models`, `app.security` or `app.tools` import. Whether those modules are
# *importable* was never the control — whether they are *imported* is.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st  # noqa: E402

from tester.audit import AuditUnavailable, read_events  # noqa: E402
from tester.client import MASK, DEFAULT_BASE_URL, ToolClient, redact  # noqa: E402
from tester.guard import assert_not_production  # noqa: E402

# First line of the app, before anything renders.
ENV = assert_not_production()

st.set_page_config(page_title="VoiceBook tester", layout="wide")


def client() -> ToolClient:
    if "client" not in st.session_state:
        st.session_state.client = ToolClient(
            base_url=st.session_state.get("base_url", DEFAULT_BASE_URL),
            call_id=f"tester-{uuid.uuid4().hex[:12]}",
        )
    return st.session_state.client


def note(record) -> None:
    """One line of feedback, and never the reference."""
    if record.ok:
        st.success(f"{record.tool} → {record.status_code}")
    elif record.status_code == 0:
        st.error(record.response["detail"])
    else:
        st.error(f"{record.tool} → {record.status_code}: {record.response.get('detail', '')}")


# --------------------------------------------------------------- sidebar

with st.sidebar:
    st.markdown("### VoiceBook tester")
    st.caption(f"ENV = `{ENV}` · channel = `tester`")
    st.text_input("API base URL", key="base_url", value=DEFAULT_BASE_URL)

    st.markdown(
        "Signs every request with the `tester` channel secret over HTTP, exactly "
        "as the phone and web channels do. No privileged path exists."
    )

    if st.button("Start a call", use_container_width=True):
        st.session_state.pop("client", None)
        result = client().call("create_session", consent_given=True)
        if result.ok:
            st.session_state.session_id = result.response["session_id"]
            st.session_state.state = result.response["state"]
            st.session_state.disclosure = result.response["disclosure"]
            st.session_state.reference = None
        note(result)

    session_id = st.session_state.get("session_id")
    st.markdown("**Session**")
    st.code(session_id or "no call in progress", language=None)
    st.markdown(f"**State** · `{st.session_state.get('state', '-')}`")

if not st.session_state.get("session_id"):
    st.info("Start a call from the sidebar.")
    st.stop()

session_id = st.session_state.session_id
api = client()

st.markdown(f"> {st.session_state.disclosure}")

left, right = st.columns([3, 2])

# ------------------------------------------------------------- the flow

with left:
    safety_tab, book_tab, cancel_tab = st.tabs(["Every turn", "Book", "Cancel"])

    with safety_tab:
        st.caption(
            "The F10 pre-filter runs before the state machine on every turn, with "
            "no provider in its path. Try an emergency or a medical question."
        )
        utterance = st.text_input("What the caller said", key="utterance")
        if st.button("Screen this turn") and utterance:
            result = api.call("screen_turn", session_id=session_id, utterance=utterance)
            note(result)
            if result.ok:
                st.session_state.state = result.response["state"]
                verdict = result.response["verdict"]
                if result.response["blocks_flow"]:
                    st.warning(f"**{verdict}** — the flow stops here.")
                    st.markdown(f"> {result.response['reply']}")
                else:
                    st.write(f"**{verdict}** — carry on.")

        st.divider()
        st.caption("Dates are resolved server-side, in the clinic's timezone (F7).")
        phrase = st.text_input("A spoken date", key="date_phrase")
        for_cancel = st.checkbox("for a cancellation (allows earlier today)")
        if st.button("Resolve date") and phrase:
            result = api.call(
                "resolve_date",
                session_id=session_id,
                phrase=phrase,
                for_cancellation=for_cancel,
            )
            note(result)
            if result.ok:
                body = result.response
                if body["resolved_date"] and body["outcome"] == "resolved":
                    st.success(f"{body['resolved_date']} — “{body['spoken']}”")
                else:
                    st.warning(f"{body['outcome']} — “{body['clarification']}”")

    with book_tab:
        query = st.text_input("Doctor or specialty", value="Cardiology", key="doctor_query")
        as_name = st.checkbox("search by doctor name instead of specialty")
        if st.button("Search doctors"):
            args = {"session_id": session_id}
            args["doctor_query" if as_name else "specialty"] = query
            result = api.call("search_doctors", **args)
            note(result)
            if result.ok:
                st.session_state.doctors = result.response["results"]
                st.session_state.doctor_resolution = result.response["resolution"]

        doctors = st.session_state.get("doctors") or []
        if doctors:
            if st.session_state.get("doctor_resolution") == "ambiguous":
                st.warning("Ambiguous — the server refused to pick. Ask the caller.")
            for entry in doctors:
                st.write(f"{entry['ordinal']}. {entry['name']} — {entry['specialty']}")

            ordinal = st.number_input(
                "Doctor ordinal", min_value=1, max_value=len(doctors), value=1
            )
            if st.button("Get slots"):
                result = api.call(
                    "get_available_slots",
                    session_id=session_id,
                    doctor_ordinal=int(ordinal),
                )
                note(result)
                if result.ok:
                    st.session_state.slots = result.response["slots"]

        slots = st.session_state.get("slots") or []
        if slots:
            for slot in slots:
                st.write(f"{slot['ordinal']}. {slot['spoken']} — {slot['doctor_name']}")

            slot_ordinal = st.number_input(
                "Slot ordinal", min_value=1, max_value=len(slots), value=1
            )
            name = st.text_input("Patient name", value="Ahmed Khan", key="book_name")
            if st.button("Confirm booking"):
                result = api.call(
                    "book_appointment",
                    session_id=session_id,
                    slot_ordinal=int(slot_ordinal),
                    patient_name=name,
                    idempotency_key=str(uuid.uuid4()),
                )
                note(result)
                if result.ok:
                    st.session_state.state = "BOOKED"
                    st.session_state.reference = result.response["reference"]

        if st.session_state.get("reference"):
            # Spoken once, at the moment of issue (5.1). It is masked in the
            # call log on the right, because that log is a transcript.
            st.success(
                "Booked. Reference **"
                + "-".join(st.session_state.reference)
                + "** — the caller needs this to cancel."
            )

    with cancel_tab:
        st.caption(
            "Name, date and reference, matched in one server-side step. Every "
            "failure returns the same message: wrong name, wrong date, wrong "
            "reference, no such record, ambiguity, lockout."
        )
        cancel_name = st.text_input("Name", value="Ahmed Khan", key="cancel_name")
        cancel_date = st.text_input("Date (yyyy-mm-dd)", key="cancel_date")

        st.markdown("**Digit buffer** — survives a cut turn (6.4)")
        fragment = st.text_input("Spoken fragment", key="fragment", placeholder="four seven")
        buttons = st.columns(2)
        if buttons[0].button("Append digits") and fragment:
            result = api.call(
                "append_reference_digits", session_id=session_id, fragment=fragment
            )
            note(result)
            if result.ok:
                st.session_state.buffer = result.response
        if buttons[1].button("Clear buffer"):
            result = api.call("clear_reference_digits", session_id=session_id)
            note(result)
            if result.ok:
                st.session_state.buffer = result.response

        buffer = st.session_state.get("buffer")
        if buffer:
            st.write(
                f"{buffer['digits_collected']} of 4 collected"
                + (f" — readback “{buffer['readback']}”" if buffer["readback"] else "")
            )
            if buffer["retries_exhausted"]:
                st.error("Two retries used. Hand off.")

        reference = st.text_input("Reference (4 digits)", key="cancel_reference", max_chars=4)
        if st.button("Attempt cancellation"):
            result = api.call(
                "cancel_appointment",
                session_id=session_id,
                patient_name=cancel_name,
                appointment_date=cancel_date,
                reference=reference,
            )
            note(result)
            if result.ok:
                st.session_state.state = "CANCELLED"
                st.success(f"Cancelled — {result.response['spoken']}")
            elif result.status_code == 403:
                st.markdown(f"> {result.response['detail']}")

# ------------------------------------------------------------- the panel

with right:
    st.markdown("#### Tool calls")
    st.caption(f"The reference is shown as {MASK} here — a call log is a transcript.")
    for record in reversed(api.history[-12:]):
        label = f"{'✓' if record.ok else '✗'} {record.tool} · {record.status_code} · {record.latency_ms:.0f} ms"
        with st.expander(label, expanded=False):
            st.json(record.safe_arguments)
            st.json(record.safe_response)

    st.markdown("#### Audit events")
    st.caption("Read directly, read-only. No endpoint exists for this.")
    try:
        for row in read_events(limit=12):
            st.write(
                f"`{row.action}` · **{row.decision}** · {row.reason}"
                + (f" · appt {row.target_appointment_id}" if row.target_appointment_id else "")
                + (f" · {row.detail}" if row.detail else "")
            )
    except AuditUnavailable as exc:
        st.caption(str(exc))
