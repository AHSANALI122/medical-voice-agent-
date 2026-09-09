"""C-11 — no f-string or .format() SQL, ever.

Greps app/ for a SQL keyword inside an interpolated string. Parameterized
queries only; the ORM's expression language counts as parameterized, a formatted
string does not.

Exit code 1 fails the build.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

APP_ROOT = Path("app")
SQL_KEYWORDS = re.compile(
    r"\b(select|insert\s+into|update|delete\s+from|drop|where|from|order\s+by)\b",
    re.IGNORECASE,
)


def _looks_like_sql(text: str) -> bool:
    return bool(SQL_KEYWORDS.search(text))


def scan(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    findings: list[str] = []

    for node in ast.walk(tree):
        # f"select ... {value}"
        if isinstance(node, ast.JoinedStr):
            literal = "".join(
                part.value for part in node.values if isinstance(part, ast.Constant)
            )
            if _looks_like_sql(literal):
                findings.append(f"{path}:{node.lineno}: f-string SQL")

        # "select ...".format(value) and "select ... %s" % value
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "format"
                and isinstance(func.value, ast.Constant)
                and isinstance(func.value.value, str)
                and _looks_like_sql(func.value.value)
            ):
                findings.append(f"{path}:{node.lineno}: .format() SQL")

        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left = node.left
            if (
                isinstance(left, ast.Constant)
                and isinstance(left.value, str)
                and _looks_like_sql(left.value)
            ):
                findings.append(f"{path}:{node.lineno}: percent-formatted SQL")

    return findings


def main() -> int:
    findings: list[str] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        findings.extend(scan(path))

    if findings:
        print("sql-interpolation: FAILED")
        for line in findings:
            print("  " + line)
        return 1

    print("sql-interpolation: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
