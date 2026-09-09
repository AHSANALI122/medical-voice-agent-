"""F12, C-16 — no provider key in any client bundle.

A build-time grep over everything shipped to a browser. Anything under
`agent/pipecat/web/` is served to the public; a secret there is a secret in a
public repository with an extra HTTP hop in front of it.

The check looks for three things:

  1. any environment variable name this project uses for a provider credential,
     or for a channel secret;
  2. anything shaped like a key — a long base64url or hex run, a provider's
     recognisable prefix;
  3. a `fetch` to a host that is not this origin, which is how a key would need
     to be used if one were smuggled in.

It is a net, not a proof, and it is worth being honest about that: the real
control is that the pipeline runs server-side and the browser is handed a room
token instead. This catches the regression where somebody "just for now" inlines
a key to get a demo working.

Exit code 1 fails the build.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BUNDLE_ROOTS = (Path("agent/pipecat/web"),)
BUNDLE_SUFFIXES = {".html", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".css", ".json"}

# Every variable that holds a credential anywhere in this project. None of them
# may be named in a file a browser downloads, even in a comment: a name is a
# strong hint about what to look for next.
FORBIDDEN_NAMES: tuple[str, ...] = (
    "VB_CHANNEL_SECRET",
    "VB_ENCRYPTION_KEY",
    "VB_REFERENCE_HMAC_KEY",
    "VB_ROOM_TOKEN_KEY",
    "VB_VAPI_WEBHOOK_SECRET",
    "DEEPGRAM_API_KEY",
    "GROQ_API_KEY",
    "ELEVENLABS_API_KEY",
    "CARTESIA_API_KEY",
    "OPENAI_API_KEY",
    "DAILY_API_KEY",
    "ANTHROPIC_API_KEY",
)

# Provider key prefixes, and anything long enough and random-looking enough to
# be a key. The length floor is set above the longest identifier that legitimately
# appears in this bundle and below the shortest key any of these providers issues.
SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("provider key prefix", re.compile(r"\b(sk-|gsk_|xi-api-|pk_live_|Bearer\s+[A-Za-z0-9._-]{20,})")),
    ("long hex run", re.compile(r"\b[0-9a-fA-F]{40,}\b")),
    ("long base64url run", re.compile(r"\b[A-Za-z0-9_-]{40,}\b")),
)

# A page that only talks to its own origin cannot use a provider key even if one
# were smuggled into it. Anything absolute is flagged for a human to look at.
CROSS_ORIGIN = re.compile(r"""(?:fetch|WebSocket|open)\s*\(\s*[`'"]https?://""")


def _bundle_files() -> list[Path]:
    files: list[Path] = []
    for root in BUNDLE_ROOTS:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix.lower() in BUNDLE_SUFFIXES:
                files.append(path)
    return files


def scan(path: Path) -> list[str]:
    findings: list[str] = []
    source = path.read_text(encoding="utf-8")

    for lineno, line in enumerate(source.splitlines(), start=1):
        for name in FORBIDDEN_NAMES:
            if name in line:
                findings.append(f"{path}:{lineno}: names the credential {name}")

        for label, pattern in SUSPICIOUS_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    f"{path}:{lineno}: {label} — {match.group(0)[:24]}…"
                )

        if CROSS_ORIGIN.search(line):
            findings.append(
                f"{path}:{lineno}: request to an absolute origin; the browser "
                f"talks only to its own server"
            )

    return findings


def main() -> int:
    files = _bundle_files()
    if not files:
        print("client-bundle: no browser bundle present yet; nothing to check")
        return 0

    findings: list[str] = []
    for path in files:
        findings.extend(scan(path))

    if findings:
        print("client-bundle: FAILED")
        for line in findings:
            print("  " + line)
        print(
            "\nNothing shipped to a browser may hold a provider key or a channel "
            "secret. The pipeline runs server-side; the browser gets a room token."
        )
        return 1

    print(f"client-bundle: clean ({len(files)} file(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
