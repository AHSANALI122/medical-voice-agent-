"""What is configured, what works, and what you can do right now.

Written because the confusing part of this project is not any one step — it is
not knowing which steps you still owe. This prints that, and nothing else.

It never prints a secret. Every check reports presence and shape: set or not,
the right length or not. A setup script that echoes keys to a terminal puts them
in a scrollback buffer, and a scrollback buffer is a file.
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

OK = "  ok  "
MISSING = " MISS "
WARN = " warn "

# Keys this project makes for itself. Absent means `scripts/init_env.py` has not
# been run, which is a thirty-second fix and needs nobody's permission.
OURS = (
    "VB_ENCRYPTION_KEY",
    "VB_REFERENCE_HMAC_KEY",
    "VB_CHANNEL_SECRET_WEB",
    "VB_CHANNEL_SECRET_PHONE",
    "VB_CHANNEL_SECRET_TESTER",
    "VB_ROOM_TOKEN_KEY",
)

# Issued by somebody else. Absent means a signup is owed. Only the audio path
# needs any of these.
THEIRS = (
    ("GROQ_API_KEY", "LLM, and Whisper STT if you want it", "console.groq.com"),
    ("DEEPGRAM_API_KEY", "STT alternative worth benchmarking", "console.deepgram.com"),
    ("ELEVENLABS_API_KEY", "phone TTS - usually set in Vapi instead", "elevenlabs.io"),
)


def _line(status: str, label: str, note: str = "") -> None:
    print(f"[{status}] {label}" + (f"  - {note}" if note else ""))


def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.4)
        return probe.connect_ex((host, port)) == 0


def check_env_file() -> bool:
    print("\n== .env ==")
    path = ROOT / ".env"
    if not path.exists():
        _line(MISSING, ".env", "run: uv run python scripts/init_env.py")
        return False

    raw = path.read_bytes()
    if b"\x00" in raw:
        # The classic Windows footgun: PowerShell's `>>` writes UTF-16LE, and
        # appending that to a UTF-8 file produces variable names nothing can
        # parse. Worth naming precisely, because the symptom is a key that looks
        # present and behaves as absent.
        _line(WARN, ".env has UTF-16 bytes in it", "PowerShell >> did this; re-run init_env.py")
        return False

    _line(OK, ".env", f"{len(raw)} bytes, clean UTF-8")
    return True


def check_our_keys() -> bool:
    print("\n== secrets this project generates for itself ==")
    import base64

    good = True
    for name in OURS:
        value = os.environ.get(name, "")
        if not value:
            _line(MISSING, name, "run: uv run python scripts/init_env.py")
            good = False
            continue
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except Exception:
            _line(MISSING, name, "not valid base64url")
            good = False
            continue
        if len(decoded) != 32:
            _line(MISSING, name, f"decodes to {len(decoded)} bytes, needs 32")
            good = False
        else:
            _line(OK, name, "32 bytes")

    webhook = os.environ.get("VB_VAPI_WEBHOOK_SECRET", "")
    if webhook:
        _line(OK, "VB_VAPI_WEBHOOK_SECRET", f"{len(webhook)} chars - paste this into Vapi")
    else:
        _line(MISSING, "VB_VAPI_WEBHOOK_SECRET", "only needed for the phone channel")
    return good


def check_provider_keys() -> None:
    print("\n== keys a provider has to issue (audio only) ==")
    for name, purpose, where in THEIRS:
        if os.environ.get(name):
            _line(OK, name, purpose)
        else:
            _line(WARN, name, f"{purpose} - get one at {where}")


def check_app() -> bool:
    print("\n== the application ==")
    try:
        from app.config import get_settings

        settings = get_settings()
    except Exception as exc:
        _line(MISSING, "configuration", f"{exc.__class__.__name__}: {exc}")
        return False

    _line(OK, "configuration loads", f"ENV={settings.env} DEMO_MODE={settings.demo_mode}")

    try:
        from app.main import create_app

        create_app()
        _line(OK, "FastAPI app builds")
    except Exception as exc:
        _line(MISSING, "FastAPI app", f"{exc.__class__.__name__}: {exc}")
        return False

    try:
        import agent  # noqa: F401
        from agent.vapi import server  # noqa: F401

        _line(OK, "agent package imports")
    except Exception as exc:
        _line(MISSING, "agent package", f"{exc.__class__.__name__}: {exc}")
        return False
    return True


def check_running() -> None:
    print("\n== processes ==")
    for port, what, how in (
        (8000, "tool API", "uv run python scripts/serve.py api"),
        (8001, "Vapi webhook", "uv run python scripts/serve.py phone"),
        (8002, "web signalling", "uv run python scripts/serve.py web"),
        (8501, "Streamlit tester", "uv run streamlit run tester/app.py"),
    ):
        if _port_open(port):
            _line(OK, f"{what} on :{port}")
        else:
            _line(WARN, f"{what} not running", how)


def check_optional_imports() -> None:
    print("\n== optional packages ==")
    for module, what, note in (
        ("streamlit", "Streamlit tester", "uv sync --group tester"),
        ("pipecat", "live web audio", "uv sync --group voice --group tester"),
    ):
        try:
            __import__(module)
            _line(OK, what)
        except ImportError:
            _line(WARN, f"{what} unavailable", note)


# Distributions that are unremarkable until they are damaged, at which point the
# symptom lands somewhere else entirely. `charset-normalizer` taught this check
# its lesson: a half-written install left files missing, `import
# charset_normalizer` still succeeded, `requests` warned that it could not find a
# character-detection dependency, and the thing that appeared broken was the
# Streamlit tester — three layers from the damage.
#
# Named as distributions, not modules, because that is what gets installed and
# what `--reinstall-package` takes.
INTEGRITY_CHECKS: tuple[tuple[str, str], ...] = (
    ("charset-normalizer", "requests, and through it Streamlit"),
    ("narwhals", "Streamlit's dataframes"),
    ("streamlit", "the text tester"),
    ("pipecat-ai", "live web audio"),
)

# A whole install cannot be verified on every run — some of these ship thousands
# of files. A sample is enough: a half-written install loses a contiguous run of
# them, not one unlucky file.
INTEGRITY_SAMPLE = 40


def missing_files(dist) -> list[str]:
    """Files the distribution says it installed that are not on disk.

    This is the question that actually matters, and it is not "does it import".
    An empty package directory still imports — Python treats it as a namespace
    package — and a package that lost half its modules imports right up until
    something touches the missing half.

    RECORD is read directly rather than through `dist.files`, and that is not
    fussiness. On Python 3.12 `dist.files` passes its result through
    `skip_missing_files`, which silently drops exactly the entries this function
    exists to find: ask the convenient API which files are missing and it
    answers "none", every time, on a wrecked install.
    """
    from pathlib import Path

    try:
        record = dist.read_text("RECORD")
    except Exception:  # noqa: BLE001 - an unreadable RECORD is "cannot tell"
        record = None
    if not record:
        # Some installs carry no RECORD. "I cannot tell" must not print as
        # "broken"; a health check that cries wolf is one people stop reading.
        return []

    recorded = [
        line.split(",", 1)[0]
        for line in record.splitlines()
        if line.strip() and not line.startswith(",")
    ]
    if not recorded:
        return []

    step = max(1, len(recorded) // INTEGRITY_SAMPLE)
    gone: list[str] = []
    for entry in recorded[::step]:
        try:
            present = Path(dist.locate_file(entry)).exists()
        except OSError:
            present = False
        if not present:
            gone.append(entry)
    return gone


def check_package_integrity() -> None:
    """Installed is not the same as importable, in either direction."""
    import importlib.metadata as metadata

    print("\n== package integrity ==")
    damaged: list[str] = []

    for name, why in INTEGRITY_CHECKS:
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue  # absent is a different problem, and reported above

        gone = missing_files(dist)
        if gone:
            damaged.append(name)
            _line(
                MISSING,
                f"{name} is installed but incomplete",
                f"breaks {why}; e.g. {gone[0]} is missing",
            )
        else:
            _line(OK, name)

    if damaged:
        print(
            "\n  An interrupted or concurrent `uv sync` leaves packages like this.\n"
            f"  Repair: uv sync --reinstall-package {' '.join(damaged)}\n"
            "  A plain `uv sync` will not fix it — as far as it is concerned,\n"
            "  those packages are already installed."
        )


def summary(env_ok: bool, keys_ok: bool, app_ok: bool) -> int:
    print("\n== what you can do right now ==")
    if env_ok and keys_ok and app_ok:
        print("  - uv run pytest                  the whole suite")
        print("  - uv run python -m evals         25 scripted conversations")
        print("  - uv run streamlit run tester/app.py   the text tester")
        print("    (start the API first: uv run python scripts/serve.py api)")
        print("\n  None of the above needs a single provider key.")
        if not os.environ.get("GROQ_API_KEY"):
            print("\n  For live audio you still owe: a Groq key. See SETUP.md.")
        return 0

    print("  Fix the MISS lines above first. In order:")
    if not env_ok or not keys_ok:
        print("    uv run python scripts/init_env.py")
    print("    uv run python scripts/doctor.py")
    return 1


def main() -> int:
    try:
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env")
    except ImportError:
        # pydantic-settings reads .env itself; this is only so the presence
        # checks below see the same values the app will.
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                name, _, value = line.partition("=")
                os.environ.setdefault(name.strip(), value.strip())

    print("VoiceBook setup check")
    print("=" * 46)

    env_ok = check_env_file()
    keys_ok = check_our_keys()
    check_provider_keys()
    app_ok = check_app()
    check_optional_imports()
    check_package_integrity()
    check_running()
    return summary(env_ok, keys_ok, app_ok)


if __name__ == "__main__":
    sys.exit(main())
