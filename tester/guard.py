"""The tester refuses to run in production (F9 acceptance).

Separated from `app.py` so it can be tested without importing Streamlit, and so
the refusal happens on the first line of the app rather than somewhere inside a
render function that a stray `st.stop()` might skip.

This is a second, independent lock. `app.config` already refuses to start the
API with `DEMO_MODE=true` under `ENV=production`; this one refuses to start the
tester at all. Neither depends on the other holding.
"""

from __future__ import annotations

import os


class RefusedInProduction(RuntimeError):
    pass


def current_env(environ: dict[str, str] | None = None) -> str:
    source = environ if environ is not None else os.environ
    return (source.get("ENV") or "development").strip().lower()


def assert_not_production(environ: dict[str, str] | None = None) -> str:
    env = current_env(environ)
    if env == "production":
        raise RefusedInProduction(
            "The Streamlit tester does not run under ENV=production. "
            "It is a development tool; there is no production mode for it."
        )
    return env
