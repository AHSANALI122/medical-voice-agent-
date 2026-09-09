"""Is the model the phone assistant is pinned to still served?

Run this first when the phone demo goes quiet. A decommissioned model id fails
in the least helpful way there is: Vapi accepts the assistant, the call never
starts, no call is recorded, and there is no error anywhere to read. Silence.

Needs `GROQ_API_KEY`. Exit code 1 if the pinned id is gone.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

GROQ_MODELS = "https://api.groq.com/openai/v1/models"
# Not chat models; excluded so the suggestion list is usable.
NOT_A_CHAT_MODEL = ("whisper", "tts", "guard", "embed")


def main() -> int:
    import os

    from agent.env import load_local_env
    from agent.vapi.assistant import MODEL_NAME, MODEL_PROVIDER

    load_local_env()

    if MODEL_PROVIDER != "groq":
        print(f"assistant uses {MODEL_PROVIDER}, not groq; nothing to check here")
        return 0

    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        print("GROQ_API_KEY is not set; cannot ask Groq what it serves", file=sys.stderr)
        return 1

    request = urllib.request.Request(
        GROQ_MODELS,
        headers={"authorization": f"Bearer {key}", "user-agent": "voicebook-setup/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            served = {m["id"] for m in json.loads(response.read())["data"]}
    except urllib.error.HTTPError as exc:
        print(f"groq refused: HTTP {exc.code}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"could not reach groq: {exc.reason}", file=sys.stderr)
        return 1

    if MODEL_NAME in served:
        print(f"model ok: {MODEL_NAME} is still served")
        return 0

    print(f"model GONE: {MODEL_NAME} is no longer served by groq", file=sys.stderr)
    print("\nchat models available on this key:", file=sys.stderr)
    for model in sorted(served):
        if not any(marker in model for marker in NOT_A_CHAT_MODEL):
            print(f"  - {model}", file=sys.stderr)
    print(
        "\nPick one, set MODEL_NAME in agent/vapi/assistant.py, then re-push:\n"
        "  uv run python scripts/push_vapi_assistant.py --url <url> --id <assistant-id>",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
