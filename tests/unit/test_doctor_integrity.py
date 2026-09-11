"""`doctor.py` can tell a half-installed distribution from a working one.

This check exists because of a real morning. Two `uv sync` runs raced, Windows
refused to overwrite a file that was open, and `charset-normalizer` was left
with files missing. `import charset_normalizer` still succeeded, so every
ordinary check passed. What failed was `requests`, which warned that it could
not find a character-detection dependency, and what *appeared* to have failed
was the Streamlit tester — three layers from the damage.

Two things are worth keeping from that.

**Importable is not installed.** An empty package directory imports fine;
Python treats it as a namespace package. A package that lost half its modules
imports right up until something touches the missing half. So the question this
asks is the one that matters: are the files the distribution says it installed
actually on disk.

**`uv sync` will not repair it.** As far as uv is concerned the package is
already there. The advice has to name `--reinstall-package`, or it sends
somebody round a loop that cannot terminate.

No test here touches the real environment. A test that empties a real dependency
to prove a point is a test that can leave a developer worse off than it found
them.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

doctor = importlib.import_module("doctor")


@pytest.fixture
def fake_dist(tmp_path):
    """A distribution on disk, with as many of its recorded files as you like
    actually present.
    """
    import importlib.metadata as metadata

    def _make(name: str, *, present: bool) -> object:
        info = tmp_path / f"{name}-1.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n", encoding="utf-8"
        )

        package = tmp_path / name.replace("-", "_")
        package.mkdir()
        recorded = ["__init__.py", "core.py", "helpers.py"]
        for filename in recorded:
            if present:
                (package / filename).write_text("", encoding="utf-8")
        (info / "RECORD").write_text(
            "".join(f"{package.name}/{f},,\n" for f in recorded), encoding="utf-8"
        )
        return metadata.Distribution.at(info)

    return _make


def test_a_distribution_missing_its_files_is_reported(fake_dist, monkeypatch, capsys):
    monkeypatch.setattr(
        doctor,
        "INTEGRITY_CHECKS",
        (("vb-fake-hollow", "something downstream"),),
    )
    monkeypatch.setattr(
        "importlib.metadata.distribution",
        lambda _name: fake_dist("vb-fake-hollow", present=False),
    )

    doctor.check_package_integrity()
    out = capsys.readouterr().out

    assert "installed but incomplete" in out
    assert doctor.MISSING in out
    assert "something downstream" in out


def test_a_complete_distribution_passes(fake_dist, monkeypatch, capsys):
    monkeypatch.setattr(
        doctor, "INTEGRITY_CHECKS", (("vb-fake-whole", "something downstream"),)
    )
    monkeypatch.setattr(
        "importlib.metadata.distribution",
        lambda _name: fake_dist("vb-fake-whole", present=True),
    )

    doctor.check_package_integrity()
    out = capsys.readouterr().out

    assert "installed but incomplete" not in out
    assert doctor.MISSING not in out


def test_the_repair_command_is_the_one_that_actually_repairs(
    fake_dist, monkeypatch, capsys
):
    """`uv sync` is the command everybody reaches for and the one that does
    nothing here.
    """
    monkeypatch.setattr(doctor, "INTEGRITY_CHECKS", (("vb-fake-hollow", "nothing"),))
    monkeypatch.setattr(
        "importlib.metadata.distribution",
        lambda _name: fake_dist("vb-fake-hollow", present=False),
    )

    doctor.check_package_integrity()
    out = capsys.readouterr().out

    assert "--reinstall-package vb-fake-hollow" in out


def test_an_absent_distribution_is_not_reported_as_damaged(monkeypatch, capsys):
    """Missing is a different problem, and the optional-packages section above
    already says so. Reporting it twice in different words sends somebody
    looking for two faults.
    """
    monkeypatch.setattr(
        doctor, "INTEGRITY_CHECKS", (("vb-not-installed-at-all", "nothing"),)
    )

    doctor.check_package_integrity()
    out = capsys.readouterr().out

    assert doctor.MISSING not in out


def test_a_distribution_that_records_nothing_is_not_called_damaged(fake_dist):
    """Some installs carry no RECORD. "I cannot tell" must not print as "broken"
    — a health check that cries wolf is one people stop reading.
    """

    class _NoRecord:
        def read_text(self, _name):
            return None

        def locate_file(self, _entry):  # pragma: no cover - never reached
            raise AssertionError("should not be asked")

    assert doctor.missing_files(_NoRecord()) == []


def test_the_convenient_api_would_have_hidden_this(fake_dist):
    """Python 3.12's `dist.files` runs its result through `skip_missing_files`,
    so it drops exactly the entries this check looks for. Asked which files are
    missing, it answers "none" on a wrecked install — which is why RECORD is
    read directly.
    """
    broken = fake_dist("vb-fake-hollow", present=False)
    assert list(broken.files or []) == []
    assert doctor.missing_files(broken)


def test_the_checked_list_names_distributions_and_not_modules():
    """`--reinstall-package` takes a distribution name. `charset_normalizer` is
    the module; `charset-normalizer` is the thing you can reinstall.
    """
    names = {name for name, _ in doctor.INTEGRITY_CHECKS}
    assert "charset-normalizer" in names
    assert "charset_normalizer" not in names
    assert "pipecat-ai" in names


def test_this_environment_is_not_currently_damaged(capsys):
    """The check, run for real. If this fails, the environment is broken and the
    fix is in the output, not in this file.
    """
    doctor.check_package_integrity()
    out = capsys.readouterr().out
    assert "installed but incomplete" not in out, out
