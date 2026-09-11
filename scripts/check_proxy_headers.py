"""C-34 — nothing in this repository starts a server that trusts X-Forwarded-For.

`uvicorn` ships with `--proxy-headers` on. With it on, uvicorn overwrites
`request.client.host` with the leftmost entry of the caller's own
`X-Forwarded-For`, before the application sees anything. Every rate-limit budget
here keys on the source address, so that default hands an abuser a fresh budget
per request by adding a header — the failure `client_ip` was written to prevent
and cannot prevent, because the rewrite happens above it.

`client_ip` in `app/security/request_auth.py` is the one place allowed to decide
what the caller's address is, governed by `VB_TRUSTED_PROXY_HOPS`. This check
keeps it the only one.

Two forms are looked for:

  1. a command line that runs `uvicorn` without `--no-proxy-headers` — in a
     README, a runbook, a workflow, a Dockerfile, a Procfile, a shell script;
  2. a `uvicorn.run(...)` call that does not pass `proxy_headers=False`.

`scripts/serve.py` is the sanctioned entry point and satisfies the second form.
A command line that invokes it satisfies the first by not mentioning uvicorn.

It is a grep, and worth being honest about that: it cannot see what somebody
types into a terminal. What it can do is stop the repository from *telling* them
to type it, and stop a deployment file from doing it for them.

Exit code 1 fails the build.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SEARCH_SUFFIXES = {
    ".md",
    ".yml",
    ".yaml",
    ".toml",
    ".sh",
    ".bash",
    ".ps1",
    ".py",
    ".cfg",
    ".ini",
    ".json",
}
SEARCH_FILENAMES = {"Procfile", "Dockerfile", "Makefile"}

# `tests` is skipped for one reason: the tests that prove this guard can fail
# have to contain the very command lines it looks for. Nothing under tests/
# starts a server anybody deploys, so the cost of the exclusion is a place a
# violation could hide where it would have no effect.
SKIP_DIRECTORIES = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "tests",
}

# This file names the flag it is looking for, in prose, many times over.
SELF = "check_proxy_headers.py"

# A shell invocation: `uvicorn app.main:app …`, with or without a runner in
# front of it. Deliberately not anchored, so `uv run uvicorn …` is caught too.
COMMAND = re.compile(r"(?<![\w./-])uvicorn\s+(?P<rest>[^\n`'\"]*)")

# A programmatic one.
RUN_CALL = re.compile(r"uvicorn\.run\s*\(")

SAFE_FLAG = "--no-proxy-headers"
SAFE_KWARG = re.compile(r"proxy_headers\s*=\s*False")


def _files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRECTORIES for part in path.parts):
            continue
        if path.name == SELF:
            continue
        if path.suffix.lower() in SEARCH_SUFFIXES or path.name in SEARCH_FILENAMES:
            found.append(path)
    return found


def _command_findings(path: Path, source: str) -> list[str]:
    findings: list[str] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        for match in COMMAND.finditer(line):
            rest = match.group("rest")
            # `uvicorn` as a bare word — a dependency pin, a sentence about the
            # library — is not an invocation. A target is what makes it one.
            if ":" not in rest and "--" not in rest:
                continue
            if SAFE_FLAG in line:
                continue
            findings.append(
                f"{path}:{lineno}: starts uvicorn without {SAFE_FLAG} — "
                f"the caller would choose their own rate-limit key"
            )
    return findings


def _run_call_findings(path: Path, source: str) -> list[str]:
    if path.suffix.lower() != ".py":
        return []

    findings: list[str] = []
    for match in RUN_CALL.finditer(source):
        # The call's arguments, up to the matching close paren. Good enough for
        # a grep: these calls are short and are never nested.
        tail = source[match.end() : match.end() + 800]
        depth = 1
        end = 0
        for index, character in enumerate(tail):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        arguments = tail[:end] if end else tail
        if SAFE_KWARG.search(arguments):
            continue
        lineno = source.count("\n", 0, match.start()) + 1
        findings.append(
            f"{path}:{lineno}: uvicorn.run() without proxy_headers=False — "
            f"uvicorn would rewrite request.client.host from X-Forwarded-For"
        )
    return findings


def scan(path: Path) -> list[str]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return _command_findings(path, source) + _run_call_findings(path, source)


def main() -> int:
    root = Path(".")
    findings: list[str] = []
    for path in _files(root):
        findings.extend(scan(path))

    if findings:
        print("proxy-headers: FAILED")
        for line in findings:
            print("  " + line)
        print(
            "\nUvicorn's --proxy-headers default overwrites request.client.host "
            "from the caller's own X-Forwarded-For. `client_ip` is the only place "
            "allowed to decide a caller's address. Start servers with "
            "`python scripts/serve.py <service>`."
        )
        return 1

    print("proxy-headers: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
