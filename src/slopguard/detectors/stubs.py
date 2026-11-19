"""SG002: Placeholder Stub & Unfinished Code Detector (tokenize-aware)."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from slopguard.models import Finding, Severity

_TODO_RE = re.compile(r"#\s*(TODO|FIXME|XXX|HACK|PLACEHOLDER)\b[:\s]*(.*)", re.IGNORECASE)
_JS_TODO_RE = re.compile(r"//\s*(TODO|FIXME|XXX|HACK|PLACEHOLDER)\b[:\s]*(.*)", re.IGNORECASE)


def _has_abstract_or_overload_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        name = ""
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        if name in {"abstractmethod", "overload"}:
            return True
    return False


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _is_stub_body(stmts: list[ast.stmt]) -> str | None:
    effective = _strip_docstring(stmts)
    if not effective:
        return "docstring-only function body"
    if len(effective) == 1:
        stmt = effective[0]
        if isinstance(stmt, ast.Pass):
            return "pass-only stub"
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
            return "ellipsis (...) stub"
        if isinstance(stmt, ast.Raise) and stmt.exc is not None:
            exc = stmt.exc
            exc_name = ""
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                exc_name = exc.func.id
            elif isinstance(exc, ast.Name):
                exc_name = exc.id
            if exc_name == "NotImplementedError":
                return "raises NotImplementedError"
    return None


def _extract_python_comments(content: str) -> list[tuple[int, int, str]]:
    comments: list[tuple[int, int, str]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                comments.append((tok.start[0], tok.start[1] + 1, tok.string))
    except tokenize.TokenError:
        pass
    return comments


def detect_stubs(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    suffix = file_path.suffix.lower()
    lines = content.splitlines()

    if suffix == ".py" and file_path.name != "__init__.py":
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return findings

        protocol_methods: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                is_protocol = any(
                    (isinstance(b, ast.Name) and b.id == "Protocol")
                    or (isinstance(b, ast.Attribute) and b.attr == "Protocol")
                    for b in node.bases
                )
                if is_protocol:
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            protocol_methods.add(item.lineno)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno in protocol_methods or _has_abstract_or_overload_decorator(node):
                    continue
                stub_reason = _is_stub_body(node.body)
                if stub_reason:
                    snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
                    findings.append(
                        Finding(
                            rule_id="SG002",
                            title="Placeholder Stub or Unfinished Code",
                            severity=Severity.HIGH,
                            category="Incomplete Implementation",
                            file_path=rel_path,
                            line=node.lineno,
                            column=node.col_offset + 1,
                            message=f"Function '{node.name}' is an unimplemented stub ({stub_reason}).",
                            snippet=snippet,
                            suggestion=f"Implement '{node.name}' or mark it explicitly as @abstractmethod / Protocol.",
                        )
                    )

        for line_no, col_no, comment_text in _extract_python_comments(content):
            m = _TODO_RE.search(comment_text)
            if m:
                tag = m.group(1).upper()
                detail = m.group(2).strip()
                findings.append(
                    Finding(
                        rule_id="SG002",
                        title="Placeholder Stub or Unfinished Code",
                        severity=Severity.LOW,
                        category="Incomplete Implementation",
                        file_path=rel_path,
                        line=line_no,
                        column=col_no,
                        message=f"Unresolved {tag} marker left in code{': ' + detail if detail else '.'}",
                        snippet=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else comment_text,
                        suggestion="Complete the pending implementation or track it as an issue before merging.",
                    )
                )

    elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        for idx, line in enumerate(lines, start=1):
            m = _JS_TODO_RE.search(line)
            if m:
                tag = m.group(1).upper()
                detail = m.group(2).strip()
                findings.append(
                    Finding(
                        rule_id="SG002",
                        title="Placeholder Stub or Unfinished Code",
                        severity=Severity.LOW,
                        category="Incomplete Implementation",
                        file_path=rel_path,
                        line=idx,
                        column=m.start() + 1,
                        message=f"Unresolved {tag} marker left in code{': ' + detail if detail else '.'}",
                        snippet=line.strip(),
                        suggestion="Complete the pending implementation or track it as an issue before merging.",
                    )
                )

    return findings
