"""Loading `.env` in the tester process (F9).

Two failures live here, and only the loud one is the reason this module exists.

The loud one: without the load the tester starts and dies on the first tool call
with `MissingSecret`, which reads like the operator skipped `init_env.py`.

The quiet one, which is the reason the ordering is asserted below: `ENV` sitting
in `.env` is invisible to a process that has not read `.env`, and
`guard.current_env` defaults to `development` when `ENV` is unset. A tester that
checks the guard before the load therefore runs happily against a file that says
`ENV=production` — the one thing F9 acceptance says it must never do.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from tester.env import NEVER_LOAD, load_local_env
from tester.guard import RefusedInProduction, assert_not_production, current_env


@pytest.fixture(autouse=True)
def restore_environment():
    """`load_local_env` writes straight into `os.environ`, which monkeypatch
    cannot undo — it only restores what monkeypatch itself changed.
    """
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


def _env_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(body, encoding="utf-8")
    return path


def test_it_reads_names_and_values(tmp_path, monkeypatch):
    monkeypatch.delenv("VB_CHANNEL_SECRET_TESTER", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    env = _env_file(tmp_path, "VB_CHANNEL_SECRET_TESTER=abc\nENV=development\n")

    assert load_local_env(env) == 2
    assert os.environ["VB_CHANNEL_SECRET_TESTER"] == "abc"


def test_an_exported_value_beats_the_file(tmp_path, monkeypatch):
    """The file is the development convenience; the real environment wins."""
    monkeypatch.setenv("VB_CHANNEL_SECRET_TESTER", "from-the-shell")
    env = _env_file(tmp_path, "VB_CHANNEL_SECRET_TESTER=from-the-file\n")

    load_local_env(env)
    assert os.environ["VB_CHANNEL_SECRET_TESTER"] == "from-the-shell"

    load_local_env(env, override=True)
    assert os.environ["VB_CHANNEL_SECRET_TESTER"] == "from-the-file"


def test_it_refuses_to_load_the_vapi_admin_credential(tmp_path, monkeypatch):
    """The tester is a development UI with a browser attached and no use for a
    credential that creates and deletes assistants.
    """
    monkeypatch.delenv("VAPI_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("VB_CHANNEL_SECRET_TESTER", raising=False)
    env = _env_file(tmp_path, "VAPI_PRIVATE_KEY=secret\nVB_CHANNEL_SECRET_TESTER=abc\n")

    assert load_local_env(env) == 1
    assert "VAPI_PRIVATE_KEY" not in os.environ
    assert "VAPI_PRIVATE_KEY" in NEVER_LOAD


def test_a_missing_file_is_not_an_error(tmp_path):
    assert load_local_env(tmp_path / "nope.env") == 0


def test_utf16_bytes_are_named_rather_than_guessed_at(tmp_path, caplog):
    """PowerShell's `>>`. The symptom is a secret that looks present and behaves
    as absent, so the log says which file and which script fixes it.
    """
    path = tmp_path / ".env"
    path.write_bytes("VB_CHANNEL_SECRET_TESTER=abc\n".encode("utf-16"))

    with caplog.at_level("WARNING", logger="voicebook.tester.env"):
        load_local_env(path)
    assert "env_file_has_utf16_bytes" in caplog.text
    assert "init_env.py" in caplog.text


def test_it_never_logs_a_value(tmp_path, caplog):
    env = _env_file(tmp_path, "VB_CHANNEL_SECRET_TESTER=super-secret-value\n")
    with caplog.at_level("DEBUG", logger="voicebook.tester.env"):
        load_local_env(env)
    assert "super-secret-value" not in caplog.text


# ------------------------------------------------------------- the ordering


def test_env_production_in_the_file_is_invisible_until_the_file_is_read(tmp_path, monkeypatch):
    """The bug this ordering prevents, stated as a fact about the guard.

    Read the file and the guard refuses. Check the guard first and it defaults
    to `development` and lets the tester run against production.
    """
    monkeypatch.delenv("ENV", raising=False)
    env = _env_file(tmp_path, "ENV=production\n")

    assert current_env() == "development"
    assert assert_not_production() == "development"

    load_local_env(env)

    assert current_env() == "production"
    with pytest.raises(RefusedInProduction):
        assert_not_production()


def test_the_tester_loads_env_before_it_checks_the_guard():
    """Asserted against the source, because importing `tester/app.py` needs
    Streamlit and would run the whole script.
    """
    source = (Path(__file__).resolve().parents[2] / "tester" / "app.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)

    calls = [
        node.value.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
    ]
    calls += [
        node.value.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
    ]

    assert "load_local_env" in calls, "tester/app.py never loads .env"
    assert "assert_not_production" in calls
    assert source.index("load_local_env()") < source.index("assert_not_production()")
