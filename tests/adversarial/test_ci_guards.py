"""The guards themselves must be able to fail.

A CI check that has never fired is a check nobody has tested. Both of these run
against a deliberately violating file to prove they catch what they claim to.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _run(script: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / script)],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_import_boundary_check_catches_a_violation(tmp_path: Path):
    agent = tmp_path / "agent" / "pipecat"
    agent.mkdir(parents=True)
    (agent / "handler.py").write_text(
        "from app.services.booking import book\n", encoding="utf-8"
    )
    result = _run("check_import_boundary.py", tmp_path)
    assert result.returncode == 1
    assert "imports app.services.booking" in result.stdout


def test_import_boundary_check_passes_on_an_http_only_agent(tmp_path: Path):
    agent = tmp_path / "agent" / "pipecat"
    agent.mkdir(parents=True)
    (agent / "handler.py").write_text(
        "import httpx\n\n\ndef call():\n    return httpx.post('https://api/tools/x')\n",
        encoding="utf-8",
    )
    result = _run("check_import_boundary.py", tmp_path)
    assert result.returncode == 0, result.stdout


def test_sql_interpolation_check_catches_an_f_string(tmp_path: Path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "bad.py").write_text(
        'def q(name):\n    return f"select * from patients where name = {name}"\n',
        encoding="utf-8",
    )
    result = _run("check_sql_interpolation.py", tmp_path)
    assert result.returncode == 1
    assert "f-string SQL" in result.stdout


def test_sql_interpolation_check_catches_format_and_percent(tmp_path: Path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "bad.py").write_text(
        'def a(n):\n    return "select * from patients where name = {}".format(n)\n\n\n'
        'def b(n):\n    return "select * from patients where name = %s" % n\n',
        encoding="utf-8",
    )
    result = _run("check_sql_interpolation.py", tmp_path)
    assert result.returncode == 1
    assert ".format() SQL" in result.stdout
    assert "percent-formatted SQL" in result.stdout


def test_the_real_repository_is_clean():
    for script in ("check_import_boundary.py", "check_sql_interpolation.py"):
        result = _run(script, REPO)
        assert result.returncode == 0, f"{script}: {result.stdout}{result.stderr}"
