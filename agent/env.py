"""Loading `.env` in the agent process (F12, F13).

The agent runs as its own process and reads its secrets from the environment —
`VB_CHANNEL_SECRET_*` for the tool API, `VB_VAPI_WEBHOOK_SECRET` for verifying
Vapi. Under `uvicorn` nothing puts a `.env` file into that environment, so
without this the process starts perfectly happily and then refuses every request
with a 401 that looks like a signature problem and is not.

It cannot borrow `app.config`, which already does this for the application: that
import is the boundary (C-19). `python-dotenv` is a third-party library, so
reading the same file independently is exactly what an external client would do.

**Called from process entry points only**, never at import time of
`agent.client`. A library that reaches out and mutates `os.environ` when it is
imported is a library that quietly changes what a test is testing.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("voicebook.agent.env")

# agent/env.py -> agent/ -> repository root
DEFAULT_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"

# Names this process refuses to load, even when they are sitting in `.env`.
#
# `VAPI_PRIVATE_KEY` is an admin credential: it creates and deletes assistants
# and reads call records. Only `scripts/push_vapi_assistant.py` ever needs it,
# and that is a command somebody runs by hand a handful of times. The webhook
# server is the one process here that faces the internet, and there is no reason
# for an admin credential to be in its environment — so it is not, regardless of
# what the file says. Keeping it in `.env` is convenient and gitignored; letting
# it reach this process is neither.
NEVER_LOAD: frozenset[str] = frozenset({"VAPI_PRIVATE_KEY"})


def load_local_env(
    path: Path | None = None, *, override: bool = False, skip: frozenset[str] = NEVER_LOAD
) -> int:
    """Read `.env` into the process environment. Returns how many names it set.

    Names in `skip` are read past, not loaded. `scripts/push_vapi_assistant.py`
    passes an empty set, because it is the one caller that legitimately wants
    the admin credential.

    `override=False` by default, so a value already exported — by a container, a
    systemd unit, a CI secret — wins over the file. The file is the development
    convenience; the real environment is the source of truth.

    Never raises and never logs a value. A missing file is an ordinary outcome:
    in a deployment there is no `.env`, there are real environment variables.
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
        log.warning(
            "env_file_has_utf16_bytes path=%s fix=scripts/init_env.py", target
        )

    loaded = 0
    for line in raw.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        name = name.strip()
        # A name with anything unusual in it came from a mangled append, not from
        # a person. Skipping it is better than exporting a variable nobody meant.
        if not name.replace("_", "").isalnum():
            continue
        if name in skip:
            continue
        value = value.strip().strip('"').strip("'")
        if not value:
            continue
        if override or name not in os.environ:
            os.environ[name] = value
            loaded += 1

    log.info("env_file_loaded path=%s names=%d", target, loaded)
    return loaded


__all__ = ["DEFAULT_ENV_PATH", "load_local_env"]
