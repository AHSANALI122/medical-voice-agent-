"""C-19 — the trust boundary is enforced by CI, not by discipline.

Nothing under agent/ may import app.services, app.db, or app.models. The agent
package talks to the API over HTTP with the same credentials as any external
caller. A boundary you can bypass with an import is not a boundary.

Exit code 1 fails the build.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

AGENT_ROOT = Path("agent")
FORBIDDEN_PREFIXES = ("app.services", "app.db", "app.models", "app.security", "app.tools")


def offending_imports(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _forbidden(alias.name):
                    found.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                # A relative import cannot climb out of agent/ into app/.
                continue
            if _forbidden(module):
                found.append((node.lineno, module))
    return found


def _forbidden(module: str) -> bool:
    return any(module == p or module.startswith(p + ".") for p in FORBIDDEN_PREFIXES)


def main() -> int:
    if not AGENT_ROOT.exists():
        print("import-boundary: agent/ not present yet; nothing to check")
        return 0

    violations: list[str] = []
    for path in sorted(AGENT_ROOT.rglob("*.py")):
        for lineno, module in offending_imports(path):
            violations.append(f"{path}:{lineno}: imports {module}")

    if violations:
        print("import-boundary: FAILED")
        for line in violations:
            print("  " + line)
        print("\nagent/ may hold an HTTP client and nothing else from this codebase.")
        return 1

    print("import-boundary: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
