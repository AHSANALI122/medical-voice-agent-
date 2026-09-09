"""Loading `.env` in the agent process (F12, F13).

Small module, but the failure it prevents is expensive to diagnose: without it
the webhook server starts cleanly and then refuses every post with a 401 that
reads like a signature problem and is not.
"""

from __future__ import annotations

import os

import pytest

from agent.env import load_local_env


@pytest.fixture(autouse=True)
def restore_environment():
    """`load_local_env` writes straight into `os.environ`, which is the whole
    point of it — and which monkeypatch cannot undo, because monkeypatch only
    restores what monkeypatch changed. Without this, one test's loaded value
    leaks into the next one's assertions.
    """
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


def test_it_reads_names_and_values(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("VB_CHANNEL_SECRET_PHONE=abc123\nVB_VAPI_WEBHOOK_SECRET=shh\n", encoding="utf-8")
    monkeypatch.delenv("VB_CHANNEL_SECRET_PHONE", raising=False)
    monkeypatch.delenv("VB_VAPI_WEBHOOK_SECRET", raising=False)

    assert load_local_env(env) == 2

    assert os.environ["VB_CHANNEL_SECRET_PHONE"] == "abc123"
    assert os.environ["VB_VAPI_WEBHOOK_SECRET"] == "shh"


def test_a_real_environment_variable_wins_over_the_file(tmp_path, monkeypatch):
    """The file is the development convenience. A container, a systemd unit or a
    CI secret is the source of truth, and must not be silently overwritten.
    """
    env = tmp_path / ".env"
    env.write_text("VB_VAPI_WEBHOOK_SECRET=from-file\n", encoding="utf-8")
    monkeypatch.setenv("VB_VAPI_WEBHOOK_SECRET", "from-the-real-environment")

    load_local_env(env)

    assert os.environ["VB_VAPI_WEBHOOK_SECRET"] == "from-the-real-environment"


def test_override_is_available_but_not_the_default(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("VB_VAPI_WEBHOOK_SECRET=from-file\n", encoding="utf-8")
    monkeypatch.setenv("VB_VAPI_WEBHOOK_SECRET", "exported")

    load_local_env(env, override=True)

    assert os.environ["VB_VAPI_WEBHOOK_SECRET"] == "from-file"


def test_comments_blanks_and_valueless_lines_are_skipped(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "# a comment\n\nDEEPGRAM_API_KEY=\nGROQ_API_KEY=gsk_x\n", encoding="utf-8"
    )
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("DEEPGRAM_API_KEY", raising=False)

    assert load_local_env(env) == 1

    assert os.environ["GROQ_API_KEY"] == "gsk_x"
    assert "DEEPGRAM_API_KEY" not in os.environ


def test_a_utf16_mangled_file_does_not_export_garbage_names(tmp_path, caplog):
    """PowerShell's `>>` writes UTF-16LE. Appended to a UTF-8 .env it produces
    names with a NUL between every character. Exporting those would put a
    variable nobody meant into the environment.
    """
    env = tmp_path / ".env"
    env.write_bytes(b"GROQ_API_KEY=good\n" + "VB_ENCRYPTION_KEY=bad\n".encode("utf-16-le"))

    with caplog.at_level("WARNING"):
        load_local_env(env)

    assert os.environ.get("GROQ_API_KEY") == "good"
    assert not any("\x00" in name for name in os.environ)
    assert "env_file_has_utf16_bytes" in caplog.text


def test_a_missing_file_is_an_ordinary_outcome(tmp_path):
    """In a deployment there is no .env — there are real environment variables."""
    assert load_local_env(tmp_path / "nope.env") == 0


def test_quoted_values_are_unwrapped(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('VB_API_URL="http://localhost:8000"\n', encoding="utf-8")
    monkeypatch.delenv("VB_API_URL", raising=False)

    load_local_env(env)

    assert os.environ["VB_API_URL"] == "http://localhost:8000"


def test_it_never_logs_a_value(tmp_path, monkeypatch, caplog):
    env = tmp_path / ".env"
    env.write_text("VB_VAPI_WEBHOOK_SECRET=super-secret-value\n", encoding="utf-8")
    monkeypatch.delenv("VB_VAPI_WEBHOOK_SECRET", raising=False)

    with caplog.at_level("INFO"):
        load_local_env(env)

    assert "super-secret-value" not in caplog.text


def test_the_admin_credential_never_reaches_the_webhook_process(tmp_path):
    """`VAPI_PRIVATE_KEY` creates and deletes Vapi assistants and reads call
    records. The webhook server is the one process here that accepts posts from
    strangers, and an admin credential has no business in its environment — so
    the loader refuses the name even when the file holds it.
    """
    from agent.env import NEVER_LOAD

    env = tmp_path / ".env"
    env.write_text(
        "VAPI_PRIVATE_KEY=admin-credential\nVB_VAPI_WEBHOOK_SECRET=runtime\n",
        encoding="utf-8",
    )

    load_local_env(env)

    assert "VAPI_PRIVATE_KEY" in NEVER_LOAD
    assert os.environ.get("VAPI_PRIVATE_KEY") is None
    # The runtime secret it does need is unaffected.
    assert os.environ["VB_VAPI_WEBHOOK_SECRET"] == "runtime"


def test_the_push_script_is_the_one_caller_allowed_to_read_it(tmp_path):
    env = tmp_path / ".env"
    env.write_text("VAPI_PRIVATE_KEY=admin-credential\n", encoding="utf-8")

    load_local_env(env, skip=frozenset())

    assert os.environ["VAPI_PRIVATE_KEY"] == "admin-credential"


def test_only_the_push_script_opts_out_of_the_denylist():
    """A second caller passing `skip=frozenset()` would quietly undo this."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    callers = [
        path
        for path in list(root.glob("agent/**/*.py")) + list(root.glob("scripts/*.py"))
        if "skip=frozenset()" in path.read_text(encoding="utf-8")
    ]
    assert [p.name for p in callers] == ["push_vapi_assistant.py"]
