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
        ("pipecat", "live web audio", "not needed until you want a microphone"),
    ):
        try:
            __import__(module)
            _line(OK, what)
        except ImportError:
            _line(WARN, f"{what} unavailable", note)


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
    check_running()
    return summary(env_ok, keys_ok, app_ok)


if __name__ == "__main__":
    sys.exit(main())
