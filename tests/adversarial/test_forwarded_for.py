"""C-34 — the caller does not get to choose their own rate-limit key.

Every abuse budget in this system keys on the source address. That only means
something if the caller cannot set it, and `X-Forwarded-For` is a header the
caller writes. `client_ip` reads it as far back as `VB_TRUSTED_PROXY_HOPS` says
there are proxies, and not at all when there are none.

The hole these tests close was not in `client_ip`. It was above it: `uvicorn`
enables `--proxy-headers` by default, and with it on, uvicorn overwrites
`request.client.host` from that same header before the application is reached.
Measured against a running server, eight requests carrying eight forged headers
produced eight separate room-token buckets — a budget of six a day, spent once
per made-up address.

Nothing in the application can defend against that, because the rewrite happens
before the application. So the defence is `scripts/serve.py`, which passes
`proxy_headers=False`, and `scripts/check_proxy_headers.py`, which fails the
build if anything in the repository starts a server any other way.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

from app.security import rate_limit
from app.security.request_auth import client_ip

REPO = Path(__file__).resolve().parents[2]
SERVE = REPO / "scripts" / "serve.py"


def _run(script: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO / "scripts" / script)],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


# --------------------------------------------------------------------------
# The behaviour the guard protects
# --------------------------------------------------------------------------


def _mint(client, forwarded: str | None = None):
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return client.post("/web/room-token", headers=headers)


def test_a_forged_header_does_not_buy_a_fresh_budget(client, db):
    """Six mints per address per day. Eight requests claiming eight addresses
    must still be eight requests from one address.

    This exercises `client_ip`, which was never the broken part — a test client
    speaks ASGI directly and no proxy middleware is in the way. It would not
    have caught the real bug and is not claimed to. It is here so that the layer
    which *is* correct stays correct while the layer above it is being fixed.
    """
    codes = [_mint(client, f"10.9.8.{i}").status_code for i in range(1, 9)]
    assert 429 in codes, (
        "every forged address got its own bucket — the budget is decorative"
    )


def test_the_buckets_do_not_multiply_with_the_header(client, db):
    before = db.query(rate_limit.RateLimitBucket).count()
    for i in range(1, 5):
        _mint(client, f"203.0.113.{i}")
    db.expire_all()
    after = db.query(rate_limit.RateLimitBucket).count()
    assert after - before <= 1, "a new bucket per forged address"


def test_with_no_proxy_configured_the_header_is_not_read():
    """`vb_trusted_proxy_hops` defaults to 0, and 0 means the peer address is
    the only thing believed.
    """

    class _Request:
        headers = {"x-forwarded-for": "10.0.0.1, 10.0.0.2"}

        class client:
            host = "198.51.100.7"

    assert client_ip(_Request()) == "198.51.100.7"


# --------------------------------------------------------------------------
# The sanctioned entry point
# --------------------------------------------------------------------------


def test_the_launcher_disables_proxy_headers():
    """Read with `ast` rather than imported: this must be true of the source,
    not of whatever a monkeypatched uvicorn happens to record.
    """
    tree = ast.parse(SERVE.read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
    ]
    assert calls, "scripts/serve.py no longer starts a server"
    for call in calls:
        keywords = {kw.arg: kw.value for kw in call.keywords}
        assert "proxy_headers" in keywords, "proxy_headers is not passed at all"
        assert isinstance(keywords["proxy_headers"], ast.Constant)
        assert keywords["proxy_headers"].value is False


def test_the_launcher_knows_all_three_processes():
    from scripts.serve import SERVICES

    assert set(SERVICES) == {"api", "phone", "web"}
    assert SERVICES["api"].factory is False
    assert SERVICES["phone"].factory is True
    assert SERVICES["web"].factory is True


def test_the_launcher_takes_no_way_to_turn_it_back_on():
    """Not a flag, not an environment variable. Both are ways for it to be true
    on the machine where it was tested and false on the one that is running.

    Asserted against the interface rather than the text: the module docstring
    names `--proxy-headers` several times, because explaining why the option is
    absent requires saying what it is called.
    """
    tree = ast.parse(SERVE.read_text(encoding="utf-8"))

    options = [
        arg.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    ]
    assert not any("proxy" in option.lower() for option in options)

    lookups = [
        node.slice.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ] + [
        arg.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    ]
    assert not any("proxy" in str(name).lower() for name in lookups)


# --------------------------------------------------------------------------
# The guard itself must be able to fail
# --------------------------------------------------------------------------


def test_the_guard_catches_a_runbook_that_tells_you_to_do_it(tmp_path: Path):
    (tmp_path / "README.md").write_text(
        "Start it with:\n\n```bash\nuv run uvicorn app.main:app --port 8000\n```\n",
        encoding="utf-8",
    )
    result = _run("check_proxy_headers.py", tmp_path)
    assert result.returncode == 1
    assert "--no-proxy-headers" in result.stdout


def test_the_guard_catches_a_deployment_file(tmp_path: Path):
    (tmp_path / "Procfile").write_text(
        "web: uvicorn app.main:app --host 0.0.0.0 --port $PORT\n", encoding="utf-8"
    )
    result = _run("check_proxy_headers.py", tmp_path)
    assert result.returncode == 1


def test_the_guard_catches_a_call_in_code(tmp_path: Path):
    (tmp_path / "run.py").write_text(
        'import uvicorn\n\nuvicorn.run("app.main:app", port=8000)\n', encoding="utf-8"
    )
    result = _run("check_proxy_headers.py", tmp_path)
    assert result.returncode == 1
    assert "proxy_headers=False" in result.stdout


def test_the_guard_accepts_the_flag_and_the_keyword(tmp_path: Path):
    (tmp_path / "README.md").write_text(
        "```bash\nuv run uvicorn app.main:app --port 8000 --no-proxy-headers\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "run.py").write_text(
        'import uvicorn\n\nuvicorn.run("app.main:app", port=8000, proxy_headers=False)\n',
        encoding="utf-8",
    )
    result = _run("check_proxy_headers.py", tmp_path)
    assert result.returncode == 0, result.stdout


def test_the_guard_does_not_fire_on_a_dependency_pin(tmp_path: Path):
    """`uvicorn` as a word is not `uvicorn` as a command."""
    (tmp_path / "pyproject.toml").write_text(
        'dependencies = ["uvicorn[standard]>=0.32"]\n', encoding="utf-8"
    )
    result = _run("check_proxy_headers.py", tmp_path)
    assert result.returncode == 0, result.stdout


def test_the_real_repository_is_clean():
    result = _run("check_proxy_headers.py", REPO)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_launcher_resolves_its_targets_from_any_directory(tmp_path: Path):
    """`python scripts/serve.py` puts `scripts/` on `sys.path`, not the repository
    root, so uvicorn's string target failed to import at all. The guard sends
    everybody through this launcher; a launcher that does not start is worse than
    the flag it replaced.
    """
    for service in ("api", "phone", "web"):
        result = subprocess.run(
            [sys.executable, str(SERVE), service, "--check"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "resolves" in result.stdout


def test_with_a_proxy_configured_only_the_hop_it_names_is_believed(monkeypatch):
    """One hop means "read one back from the end", not "read what the client
    wrote". The leftmost entry is the caller's own and is never the answer —
    which is precisely where uvicorn's version differs, and why it had to go.
    """
    from app.config import reset_settings_cache

    monkeypatch.setenv("VB_TRUSTED_PROXY_HOPS", "1")
    reset_settings_cache()
    try:

        class _Request:
            headers = {"x-forwarded-for": "10.0.0.1, 203.0.113.9"}

            class client:
                host = "127.0.0.1"

        assert client_ip(_Request()) == "203.0.113.9"
    finally:
        reset_settings_cache()
