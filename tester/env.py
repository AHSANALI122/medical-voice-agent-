"""Loading `.env` in the tester process (F9).

Streamlit runs `tester/app.py` as a script. Nothing in that path puts `.env`
into the environment: `app.config` reads the file for the API, but the tester
cannot import it (C-19), and `streamlit run` is not `uv run` with a settings
object behind it. Without this the tester starts and then dies on the first
call with `MissingSecret`, which reads like a setup mistake and is not one.

The same reasoning as `agent/env.py`, for the same reason, one package over.
Neither imports the other: the tester is an external client of the tool API and
stays standalone, so deleting `agent/` must not break it. The parsing itself is
`python-dotenv`'s — declared in `pyproject.toml` precisely so the untrusted side
can read the file without borrowing `app.config`.

**Ordering matters.** `guard.current_env` defaults to `development` when `ENV`
is unset, so a tester that has not read `.env` yet cannot see `ENV=production`
in it and will happily start. The load belongs above `assert_not_production`,
not merely above the first tool call.

**Called from the process entry point only**, never at import time of
`tester.client` — a module that mutates `os.environ` when imported changes what
every test that imports it is testing.
"""

from __future__ import annotations

import io
import logging
import os
from pathlib import Path

from dotenv import dotenv_values

log = logging.getLogger("voicebook.tester.env")

# tester/env.py -> tester/ -> repository root
DEFAULT_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"

# Names this process refuses to load, even when they are sitting in `.env`.
#
# `VAPI_PRIVATE_KEY` creates and deletes assistants and reads call records. Only
# `scripts/push_vapi_assistant.py` needs it. The tester is a development UI with
# a browser attached to it and no use for an admin credential whatsoever, so it
# does not get one, regardless of what the file says.
NEVER_LOAD: frozenset[str] = frozenset({"VAPI_PRIVATE_KEY"})


def load_local_env(
    path: Path | None = None, *, override: bool = False, skip: frozenset[str] = NEVER_LOAD
) -> int:
    """Read `.env` into the process environment. Returns how many names it set.

    `override=False` by default, so a value already exported — by a container, a
    CI secret, a shell — wins over the file. The file is the development
    convenience; the real environment is the source of truth.

    Never raises and never logs a value. A missing file is an ordinary outcome.
    """
    target = path or DEFAULT_ENV_PATH
    if not target.exists():
        return 0

    try:
        raw = target.read_bytes()
    except OSError:
        return 0

    if b"\x00" in raw:
        # PowerShell's `>>` writes UTF-16LE. Appending that to a UTF-8 `.env`
        # produces variable names nothing can parse, and the symptom is a secret
        # that looks present and behaves as absent. Worth naming, not guessing at.
        log.warning("env_file_has_utf16_bytes path=%s fix=scripts/init_env.py", target)

    # Decoded here rather than handed to `dotenv_values` as a path: a mangled
    # file makes it raise, and refusing to start over a damaged `.env` is a
    # worse failure than the one this module exists to prevent. Decode
    # permissively, parse what survives, and let the warning above explain the
    # names that did not.
    parsed = dotenv_values(stream=io.StringIO(raw.decode("utf-8", errors="replace")))

    loaded = 0
    for name, value in parsed.items():
        if not name or not value or name in skip:
            continue
        # A name with anything unusual in it came from a mangled append, not
        # from a person. Skipping it beats exporting a variable nobody meant.
        if not name.replace("_", "").isalnum():
            continue
        if override or name not in os.environ:
            os.environ[name] = value
            loaded += 1

    log.info("env_file_loaded path=%s names=%d", target, loaded)
    return loaded


__all__ = ["DEFAULT_ENV_PATH", "NEVER_LOAD", "load_local_env"]
