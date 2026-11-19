"""SG003: Silent Failure & Swallowed Exception Detector."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from slopguard.models import Finding, Severity

_JS_EMPTY_CATCH_RE = re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}", re.DOTALL)


def _is_swallowed_body(body: list[ast.stmt]) -> bool:
    if len(body) != 1:
        return False
    stmt = body[0]
    if isinstance(stmt, (ast.Pass, ast.Continue)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
        return True
    if isinstance(stmt, ast.Return):
        val = stmt.value
        if val is None:
            return True
        if isinstance(val, ast.Constant) and val.value in (None, False, ""):
            return True
        if isinstance(val, (ast.List, ast.Dict, ast.Tuple)) and not val.elts if hasattr(val, "elts") else isinstance(val, ast.Dict) and not val.keys:
            return True
    return False


def detect_silent_errors(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    suffix = file_path.suffix.lower()
    lines = content.splitlines()

    if suffix == ".py":
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                is_bare = node.type is None
                is_broad = (
                    isinstance(node.type, ast.Name)
                    and node.type.id in {"Exception", "BaseException"}
                )
                if is_bare:
                    snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
                    findings.append(
                        Finding(
                            rule_id="SG003",
                            title="Silent Failure / Swallowed Exception",
                            severity=Severity.HIGH,
                            category="Error Handling Anti-Pattern",
                            file_path=rel_path,
                            line=node.lineno,
                            column=node.col_offset + 1,
                            message="Bare 'except:' catches SystemExit and KeyboardInterrupt as well as all errors.",
                            snippet=snippet,
                            suggestion="Catch a specific exception class and log or handle the failure explicitly.",
                        )
                    )
                elif is_broad and _is_swallowed_body(node.body):
                    snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
                    findings.append(
                        Finding(
                            rule_id="SG003",
                            title="Silent Failure / Swallowed Exception",
                            severity=Severity.HIGH,
                            category="Error Handling Anti-Pattern",
                            file_path=rel_path,
                            line=node.lineno,
                            column=node.col_offset + 1,
                            message="Broad 'except Exception:' silently swallows errors.",
                            snippet=snippet,
                            suggestion="Log the exception or narrow the caught exception type instead of swallowing it.",
                        )
                    )

    elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        for m in _JS_EMPTY_CATCH_RE.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append(
                Finding(
                    rule_id="SG003",
                    title="Silent Failure / Swallowed Exception",
                    severity=Severity.HIGH,
                    category="Error Handling Anti-Pattern",
                    file_path=rel_path,
                    line=line_no,
                    column=1,
                    message="Empty catch block silently swallows runtime exceptions.",
                    snippet=snippet,
                    suggestion="Log or rethrow the error instead of leaving an empty catch block.",
                )
            )

    return findings
