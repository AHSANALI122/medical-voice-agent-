"""Create or update the Vapi assistant from `agent/vapi/assistant.py`.

Hand-pasting a hundred lines of JSON into a dashboard is where a tool argument
quietly goes missing, and a missing argument in this system is a tool the model
can call with a field the server never validated. The config has one definition;
this pushes it.

Two things it will not do.

**It never writes your private key anywhere.** It reads `VAPI_PRIVATE_KEY` from
the environment or from `.env`, and prompts without echo if neither has it. The
key is used for one request and dropped — never logged, never in the output.

Keeping it in `.env` is fine: that file is gitignored and it is on your own
machine. What matters is that it goes no further, and `agent.env.NEVER_LOAD`
enforces that — the webhook server, the one process here that faces the
internet, refuses to load this name even when it is sitting in the file. An
admin credential that creates and deletes assistants has no business in a
process that accepts posts from strangers.

**It never sets a phone number.** `build_assistant` has no `phoneNumberId` and
this script adds none. The number is attached in the dashboard, during a
recording window, and detached afterwards (§2). A script that could attach a
number is a script that could leave one attached.

Usage:

    # See exactly what would be sent, without sending it.
    uv run python scripts/push_vapi_assistant.py --url https://x.ngrok.app/vapi/tools --dry-run

    # Create it.
    uv run python scripts/push_vapi_assistant.py --url https://x.ngrok.app/vapi/tools

    # Update it later (the id is printed on creation).
    uv run python scripts/push_vapi_assistant.py --url https://x.ngrok.app/vapi/tools --id <assistant-id>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

VAPI_API = "https://api.vapi.ai/assistant"


def _redacted(payload: dict) -> str:
    """The config, safe to print. It holds no secret, and this keeps it that way
    if somebody later adds one.
    """
    text = json.dumps(payload, indent=2)
    for name in ("VAPI_PRIVATE_KEY", "VB_VAPI_WEBHOOK_SECRET"):
        value = os.environ.get(name)
        if value and value in text:
            text = text.replace(value, f"<{name}>")
    return text


# Vapi's API sits behind Cloudflare, which blocks the default `Python-urllib/3.x`
# user agent outright — the symptom is an HTTP 403 carrying "error code: 1010",
# which reads exactly like a rejected credential and is not one. An honest name
# for this client gets through.
USER_AGENT = "voicebook-setup/1.0 (+scripts/push_vapi_assistant.py)"


def _request(url: str, payload: dict, key: str, method: str) -> dict:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {key}",
            "user-agent": USER_AGENT,
            "accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--url",
        required=True,
        help="the public webhook URL, ending in /vapi/tools",
    )
    parser.add_argument("--id", help="assistant id to update; omit to create a new one")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the payload and send nothing",
    )
    args = parser.parse_args(argv)

    if not args.url.startswith("https://"):
        # Vapi posts your webhook secret with every call. Over http that secret
        # is on the wire in clear, and the secret is the whole authentication.
        print("the webhook URL must be https - Vapi sends the secret over it", file=sys.stderr)
        return 1
    if not args.url.rstrip("/").endswith("/vapi/tools"):
        print(f"warning: {args.url} does not end in /vapi/tools", file=sys.stderr)

    from agent.env import load_local_env
    from agent.vapi.assistant import build_assistant

    # `skip=frozenset()` on purpose: this is the one command that is allowed to
    # read the admin credential out of .env. The webhook server calls the same
    # function with the default denylist and never sees it.
    load_local_env(skip=frozenset())
    payload = build_assistant(webhook_url=args.url)

    if not os.environ.get("VB_VAPI_WEBHOOK_SECRET"):
        print(
            "warning: VB_VAPI_WEBHOOK_SECRET is not set locally. The assistant "
            "will be created, but your webhook will refuse every call until the "
            "same secret is set here and in the dashboard.",
            file=sys.stderr,
        )

    if args.dry_run:
        print(_redacted(payload))
        print(
            f"\n-- dry run, nothing sent. {len(payload['model']['tools'])} tools, "
            f"maxDurationSeconds={payload['maxDurationSeconds']}",
            file=sys.stderr,
        )
        return 0

    key = os.environ.get("VAPI_PRIVATE_KEY", "")
    if not key:
        # Prompted, rather than read from `.env` and rather than taken from the
        # command line. Three reasons, in the order each is likely to bite:
        #
        #   It is an admin credential — it creates and deletes assistants and
        #   reads call records. Nothing this project runs at runtime needs it,
        #   so in `.env` it would be loaded into the webhook process, the one
        #   process here that faces the internet, for no benefit whatsoever.
        #
        #   Typed as `VAPI_PRIVATE_KEY=... command`, it lands in the shell's
        #   history file, which is plaintext and outlives the terminal.
        #
        #   getpass does not echo, so it does not reach the scrollback either.
        #   It lives in this process and dies with it.
        if not sys.stdin.isatty():
            # No terminal to prompt at — a pipe, a CI job, a hook. `getpass`
            # would block on the tty forever here, and a script that hangs in
            # CI is worse than one that fails, because nobody sees why.
            print(
                "VAPI_PRIVATE_KEY is not set and there is no terminal to ask at.\n"
                "Export it for this one command, or run this from a terminal and "
                "be prompted:\n"
                "  VAPI_PRIVATE_KEY=... uv run python scripts/push_vapi_assistant.py --url ...",
                file=sys.stderr,
            )
            return 1

        try:
            import getpass

            print(
                "Vapi private key needed - dashboard, API Keys, the PRIVATE one.\n"
                "Not saved anywhere: not to .env, not to shell history, not to "
                "the screen.",
                file=sys.stderr,
            )
            key = getpass.getpass("VAPI_PRIVATE_KEY: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\ncancelled; nothing was sent", file=sys.stderr)
            return 1

    if not key:
        print("no key given; nothing was sent", file=sys.stderr)
        return 1

    url = f"{VAPI_API}/{args.id}" if args.id else VAPI_API
    method = "PATCH" if args.id else "POST"

    try:
        result = _request(url, payload, key, method)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:600]
        print(f"vapi refused the request: HTTP {exc.code}\n{detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"could not reach vapi: {exc.reason}", file=sys.stderr)
        return 1

    assistant_id = result.get("id", "<no id returned>")
    print(f"{'updated' if args.id else 'created'} assistant {assistant_id}")
    print(f"  webhook  {args.url}")
    print(f"  tools    {len(payload['model']['tools'])}")
    print(f"  max call {payload['maxDurationSeconds']}s")
    print(
        "\nNow set the Server URL Secret for this assistant in the dashboard to "
        "the value of VB_VAPI_WEBHOOK_SECRET in your .env. Vapi sends it as the "
        "X-Vapi-Secret header and agent/vapi/webhook.py verifies it."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
