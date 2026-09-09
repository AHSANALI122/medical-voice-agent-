"""C-19, C-13 — the trust boundary is enforced by CI, not by discipline.

Nothing under agent/ or tester/ may import app.services, app.db, or app.models.
Both packages talk to the API over HTTP with the same credentials as any external
caller. A boundary you can bypass with an import is not a boundary.

tester/ is checked for the same reason agent/ is, and it is the whole answer to
C-13: the Streamlit tester is not a backdoor because it *cannot* reach the
service layer, not because nobody has written the import yet.

Exit code 1 fails the build.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

UNTRUSTED_ROOTS = (Path("agent"), Path("tester"))
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
    present = [root for root in UNTRUSTED_ROOTS if root.exists()]
    if not present:
        print("import-boundary: no untrusted package present yet; nothing to check")
        return 0

    violations: list[str] = []
    for root in present:
        for path in sorted(root.rglob("*.py")):
            for lineno, module in offending_imports(path):
                violations.append(f"{path}:{lineno}: imports {module}")

    if violations:
        print("import-boundary: FAILED")
        for line in violations:
            print("  " + line)
        print(
            "\nagent/ and tester/ may hold an HTTP client and nothing else "
            "from this codebase."
        )
        return 1

    print("import-boundary: clean (" + ", ".join(str(r) for r in present) + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
