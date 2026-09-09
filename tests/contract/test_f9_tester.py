"""F9 — the Streamlit tester (C-13).

C-13 is the finding that a testing tool becomes a backdoor. The acceptance
criteria are therefore mostly negative: no privileged path, no extra endpoint, no
production mode. Each one is asserted here rather than argued.

`tester/app.py` is not imported: it needs Streamlit, and everything worth testing
was deliberately kept out of it.
"""

from __future__ import annotations

import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from app.security import request_auth
from app.security.reference import UNIFORM_FAILURE_TEXT
from tester import audit, client as tester_client
from tester.guard import RefusedInProduction, assert_not_production


@pytest.fixture
def tester(app) -> tester_client.ToolClient:
    """The tester, wired to the app over the same signed HTTP path a deployed
    one would use. No fixture here has a shortcut the real tool lacks.
    """
    return tester_client.ToolClient(
        channel="tester", http=TestClient(app, base_url="http://testserver")
    )


# ------------------------------------------------------- refuses production


def test_the_tester_refuses_to_start_in_production():
    with pytest.raises(RefusedInProduction):
        assert_not_production({"ENV": "production"})
    with pytest.raises(RefusedInProduction):
        assert_not_production({"ENV": "  PRODUCTION  "})


def test_the_tester_starts_anywhere_else():
    for env in ({"ENV": "development"}, {"ENV": "test"}, {}):
        assert assert_not_production(env) in {"development", "test"}


# ------------------------------------------------- the identical signed path


def test_the_testers_signature_matches_the_servers_canonical_form():
    """The signing code is duplicated on purpose, so this is the test that keeps
    the copy honest. If the server changes its canonical form, this fails here
    rather than in a demo.
    """
    secret = b"\x01" * 32
    args = ("1700000000", "abc123def456", b'{"a":1}', "call-9")
    assert tester_client.sign(secret, *args) == request_auth.sign(secret, *args)
    # And with no call id, which is the web channel's shape.
    assert tester_client.sign(secret, args[0], args[1], args[2]) == request_auth.sign(
        secret, args[0], args[1], args[2]
    )


def test_the_tester_completes_a_whole_booking_and_cancellation(tester):
    """The full flow in text, through the public API, with nothing skipped."""
    session = tester.call("create_session", consent_given=True)
    assert session.ok
    session_id = session.response["session_id"]

    assert tester.call(
        "search_doctors", session_id=session_id, specialty="Cardiology"
    ).ok
    assert tester.call(
        "get_available_slots", session_id=session_id, doctor_ordinal=1
    ).ok

    booked = tester.call(
        "book_appointment",
        session_id=session_id,
        slot_ordinal=1,
        patient_name="Ahmed Khan",
        idempotency_key=str(uuid.uuid4()),
    )
    assert booked.ok
    reference = booked.response["reference"]
    day = booked.response["starts_at_local"][:10]

    cancelled = tester.call(
        "cancel_appointment",
        session_id=session_id,
        patient_name="Ahmed Khan",
        appointment_date=day,
        reference=reference,
    )
    assert cancelled.ok
    assert cancelled.response["confirmed"] is True


def test_the_tester_has_no_way_to_cancel_without_the_reference(tester):
    """C-13 and the §2 decision in one test: there is no minimal mode, no flag,
    and no tester-only path that cancels on a name and a date.
    """
    session_id = tester.call("create_session", consent_given=True).response["session_id"]
    tester.call("search_doctors", session_id=session_id, specialty="Cardiology")
    tester.call("get_available_slots", session_id=session_id, doctor_ordinal=1)
    booked = tester.call(
        "book_appointment",
        session_id=session_id,
        slot_ordinal=1,
        patient_name="Ahmed Khan",
        idempotency_key=str(uuid.uuid4()),
    )
    day = booked.response["starts_at_local"][:10]

    # Omitting it is not expressible: the shape is wrong.
    omitted = tester.call(
        "cancel_appointment",
        session_id=session_id,
        patient_name="Ahmed Khan",
        appointment_date=day,
    )
    assert omitted.status_code == 422

    # Guessing it is a denial, and the same denial everyone else gets.
    wrong = tester.call(
        "cancel_appointment",
        session_id=session_id,
        patient_name="Ahmed Khan",
        appointment_date=day,
        reference="0000" if booked.response["reference"] != "0000" else "1111",
    )
    assert wrong.status_code == 403
    assert wrong.response["detail"] == UNIFORM_FAILURE_TEXT


# --------------------------------------------------------- no extra surface


def _tool_paths(app) -> set[str]:
    """The API's own surface, read from the generated schema.

    Not from `app.routes`: FastAPI nests an included router behind an opaque
    object, so a shallow walk finds nothing and an assertion built on one passes
    while proving nothing. The schema is the published answer to "what endpoints
    exist", which is the question being asked.
    """
    return {
        path.removeprefix("/tools/")
        for path in app.openapi()["paths"]
        if path.startswith("/tools/")
    }


def test_the_testers_tool_list_is_exactly_the_apis_tool_surface(app):
    """F9 acceptance, both directions.

    No endpoint reachable by the tester and not by the voice channels — and no
    endpoint the tester has quietly stopped exercising, which is how a tested
    flow and a shipped flow drift apart.
    """
    routes = _tool_paths(app)
    assert routes, "no /tools/* routes found — the walk is wrong, not the API"
    assert set(tester_client.TOOLS) == routes


@pytest.mark.parametrize("channel", ["web", "phone", "tester"])
def test_every_tool_is_reachable_from_every_channel(channel, app):
    """No channel has a privileged path (§1.1), and none has a diminished one.

    Each tool is called with a deliberately empty body: a 422 proves the endpoint
    is there and authenticated the caller, and a 401 would prove it did not.
    """
    caller = tester_client.ToolClient(
        channel=channel, http=TestClient(app, base_url="http://testserver")
    )
    for tool in tester_client.TOOLS:
        record = caller.call(tool)
        assert record.status_code != 401, f"{channel} refused at {tool}"
        assert record.status_code in {200, 403, 422}, f"{channel} {tool} {record.status_code}"


# -------------------------------------------------------------- redaction


def test_the_reference_is_masked_in_the_call_log(tester):
    """The call log is a transcript by another name, and a reference must not
    outlive the moment it was disclosed in.
    """
    session_id = tester.call("create_session", consent_given=True).response["session_id"]
    tester.call("search_doctors", session_id=session_id, specialty="Cardiology")
    tester.call("get_available_slots", session_id=session_id, doctor_ordinal=1)
    booked = tester.call(
        "book_appointment",
        session_id=session_id,
        slot_ordinal=1,
        patient_name="Ahmed Khan",
        idempotency_key=str(uuid.uuid4()),
    )

    reference = booked.response["reference"]
    assert booked.safe_response["reference"] == tester_client.MASK
    assert reference not in str(booked.safe_response)

    cancelled = tester.call(
        "cancel_appointment",
        session_id=session_id,
        patient_name="Ahmed Khan",
        appointment_date=booked.response["starts_at_local"][:10],
        reference=reference,
    )
    assert cancelled.safe_arguments["reference"] == tester_client.MASK
    assert reference not in str(cancelled.safe_arguments)


def test_redaction_reaches_into_nested_shapes():
    payload = {"results": [{"reference": "4729", "name": "Ahmed"}], "reference": "4729"}
    masked = tester_client.redact(payload)
    assert "4729" not in str(masked)
    assert masked["results"][0]["name"] == "Ahmed"


def test_an_unreachable_api_is_a_failed_call_not_a_crash():
    """C-30 applied to the tester itself.

    A tool that dies with a stack trace when the server is down teaches nothing
    about the failure it exists to model — and it is the first thing that
    happens to anyone who starts the tester before the API.
    """
    offline = tester_client.ToolClient(
        base_url="http://127.0.0.1:9", secret=b"\x00" * 32
    )
    record = offline.call("create_session", consent_given=True)
    assert record.status_code == 0
    assert not record.ok
    assert "could not reach the API" in record.response["detail"]
    assert offline.history == [record]


def test_every_call_records_its_arguments_status_and_latency(tester):
    tester.call("create_session", consent_given=True)
    record = tester.history[-1]
    assert record.tool == "create_session"
    assert record.arguments == {"consent_given": True}
    assert record.status_code == 200
    assert record.latency_ms >= 0


# ------------------------------------------------------------ audit panel


def test_the_audit_panel_reads_the_table_directly_and_read_only(tmp_path):
    """No endpoint exists for this, on purpose: an /audit endpoint built for the
    tester would be exactly the extra surface F9 forbids.
    """
    path = tmp_path / "voicebook.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE audit_events ("
        "id INTEGER PRIMARY KEY, created_at TEXT, session_id TEXT, channel TEXT, "
        "action TEXT, target_appointment_id INTEGER, decision TEXT, reason TEXT, detail TEXT)"
    )
    connection.execute(
        "INSERT INTO audit_events VALUES (1,'2026-03-02','s1','tester',"
        "'cancel_appointment',7,'denied','no_match',NULL)"
    )
    connection.commit()
    connection.close()

    rows = audit.read_events(limit=5, path=str(path))
    assert len(rows) == 1
    assert rows[0].action == "cancel_appointment"
    assert rows[0].decision == "denied"


def test_the_audit_connection_cannot_write(tmp_path):
    """`mode=ro` is enforced by SQLite, not by this module's good intentions."""
    path = tmp_path / "voicebook.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE audit_events (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()

    read_only = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            read_only.execute("INSERT INTO audit_events VALUES (1)")
    finally:
        read_only.close()


def test_an_unreadable_database_is_a_note_not_a_crash():
    with pytest.raises(audit.AuditUnavailable):
        audit.read_events(path=":memory:")
    with pytest.raises(audit.AuditUnavailable):
        audit.read_events(path="no/such/file.db")


# ------------------------------------------------------------- the secret


def test_the_secret_comes_from_the_environment_only():
    with pytest.raises(tester_client.MissingSecret):
        tester_client.channel_secret("tester", environ={})
    assert tester_client.channel_secret(
        "tester", environ={"VB_CHANNEL_SECRET_TESTER": "AAAAAAAAAAAAAAAAAAAAAA"}
    )


# --------------------------------------------------------------------------
# Streamlit runs app.py as a script, not as a module
# --------------------------------------------------------------------------


def test_the_tester_imports_the_way_streamlit_runs_it():
    """`streamlit run tester/app.py` puts `tester/` on `sys.path[0]`, not the
    repository root, so `from tester.audit import ...` fails with
    `ModuleNotFoundError: No module named 'tester'`.

    The failure is invisible from outside: the Streamlit server starts, the port
    answers, `/_stcore/health` says `ok`, and the traceback appears only in the
    browser. So this asserts the thing a port check cannot — that the script's
    imports resolve in the context Streamlit actually gives them.
    """
    import ast
    import pathlib
    import subprocess
    import sys
    import textwrap

    root = pathlib.Path(__file__).resolve().parents[2]
    app = root / "tester" / "app.py"

    # Execute only app.py's import prologue — everything up to the first
    # statement that touches Streamlit's runtime. Importing the whole file would
    # need a live Streamlit session, which is not what is under test here.
    tree = ast.parse(app.read_text(encoding="utf-8"))
    prologue: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            getattr(t, "id", "") == "ENV" for t in node.targets
        ):
            break
        # `from __future__` has to be the first statement of a file, and this
        # snippet is spliced under a preamble. It has no bearing on whether the
        # sibling imports resolve, which is what is under test.
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        prologue.append(node)

    source = ast.unparse(ast.Module(body=prologue, type_ignores=[]))
    script = textwrap.dedent(
        f"""
        import sys, pathlib
        # Exactly what `streamlit run` does: the script's own directory first.
        sys.path.insert(0, str(pathlib.Path.cwd()))
        __file__ = str(pathlib.Path("app.py").resolve())
        {textwrap.indent(source, "        ").lstrip()}
        print("ok")
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=root / "tester",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_the_path_bootstrap_does_not_smuggle_in_the_service_layer():
    """The bootstrap puts the repository root on `sys.path`, which makes `app.*`
    importable. That is fine and is not the control: the boundary is enforced by
    `scripts/check_import_boundary.py` parsing what is actually imported. This
    asserts the tester still imports none of it.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    source = (root / "tester" / "app.py").read_text(encoding="utf-8")
    for module in ("app.services", "app.db", "app.models", "app.security", "app.tools"):
        assert f"import {module}" not in source
        assert f"from {module}" not in source
