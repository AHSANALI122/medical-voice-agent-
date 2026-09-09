"""Fill in every secret this project generates for itself.

There are two kinds of secret in `.env` and confusing them is the thing that
makes setup feel hard:

  **Ours.** `VB_ENCRYPTION_KEY`, the three channel secrets, the room-token key,
  the Vapi webhook secret. Nobody issues these. They are random bytes, and this
  script makes them. No signup, no dashboard, no waiting.

  **Theirs.** `GROQ_API_KEY`, `DEEPGRAM_API_KEY`, and friends. These come from a
  provider's console and this script cannot invent them. It leaves them alone
  and says so.

Idempotent, and deliberately so: a value that is already set is never touched.
Re-running this after adding a provider key does not rotate the keys that are
already protecting rows in the database.

Nothing is printed except the names of the variables that were filled. The
values go to the file and nowhere else — not to a log, not to the terminal, not
to this process's output. `.env` is gitignored and `gitleaks` runs pre-commit.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
EXAMPLE_PATH = ROOT / ".env.example"

KEY_BYTES = 32

# 32 raw bytes, base64url. `app.config` decodes these and refuses anything that
# is not exactly this long.
GENERATED_KEYS: tuple[str, ...] = (
    "VB_ENCRYPTION_KEY",
    "VB_REFERENCE_HMAC_KEY",
    "VB_CHANNEL_SECRET_WEB",
    "VB_CHANNEL_SECRET_PHONE",
    "VB_CHANNEL_SECRET_TESTER",
    "VB_ROOM_TOKEN_KEY",
)

# Not a 32-byte key — an arbitrary shared string. It has to be pasted into the
# Vapi dashboard verbatim, so it is url-safe and has no padding to lose.
GENERATED_TOKENS: tuple[str, ...] = ("VB_VAPI_WEBHOOK_SECRET",)

# Left empty on purpose. A provider issues these; see SETUP.md.
PROVIDER_KEYS: tuple[str, ...] = (
    "GROQ_API_KEY",
    "DEEPGRAM_API_KEY",
    "ELEVENLABS_API_KEY",
)


def _new_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(KEY_BYTES)).decode().rstrip("=")


def _new_token() -> str:
    return secrets.token_urlsafe(KEY_BYTES)


def _split(line: str) -> tuple[str, str] | None:
    """Parse one `NAME=value` line. Comments and blanks return None."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    name, _, value = stripped.partition("=")
    return name.strip(), value.strip()


def fill(text: str) -> tuple[str, list[str], list[str]]:
    """Return the updated file, what was filled, and what still needs a human."""
    filled: list[str] = []
    out: list[str] = []

    for line in text.splitlines():
        parsed = _split(line)
        if parsed is None:
            out.append(line)
            continue

        name, value = parsed
        if value:
            # Already set. Never rotated by this script: rotating an encryption
            # key silently orphans every row encrypted under the old one.
            out.append(line)
            continue

        if name in GENERATED_KEYS:
            out.append(f"{name}={_new_key()}")
            filled.append(name)
        elif name in GENERATED_TOKENS:
            out.append(f"{name}={_new_token()}")
            filled.append(name)
        else:
            out.append(line)

    missing = [
        name
        for name in PROVIDER_KEYS
        if not dict(
            p for p in (_split(line) for line in out) if p is not None
        ).get(name)
    ]
    return "\n".join(out) + "\n", filled, missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--force-rotate",
        action="store_true",
        help=(
            "Regenerate every generated key, even ones already set. Invalidates "
            "every reference and encrypted row already in the database."
        ),
    )
    args = parser.parse_args(argv)

    if not ENV_PATH.exists():
        if not EXAMPLE_PATH.exists():
            print("no .env and no .env.example to build one from", file=sys.stderr)
            return 1
        shutil.copy(EXAMPLE_PATH, ENV_PATH)
        print("created .env from .env.example")

    text = ENV_PATH.read_text(encoding="utf-8")

    if args.force_rotate:
        for name in GENERATED_KEYS + GENERATED_TOKENS:
            text = "\n".join(
                f"{name}=" if (_split(line) or ("", ""))[0] == name else line
                for line in text.splitlines()
            )

    updated, filled, missing = fill(text)
    ENV_PATH.write_text(updated, encoding="utf-8")

    if filled:
        print(f"filled {len(filled)} generated secret(s):")
        for name in filled:
            print(f"  {name}")
    else:
        print("every generated secret was already set; nothing changed")

    if missing:
        print("\nstill empty — these come from a provider, not from here:")
        for name in missing:
            print(f"  {name}")
        print("\nThey are only needed for live audio. See SETUP.md.")

    print("\nNext: uv run python scripts/doctor.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
