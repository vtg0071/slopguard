"""SG008: Structural & Code-Quality Slop Detector."""

from __future__ import annotations

import ast
from pathlib import Path

from slopguard.models import Finding, Severity

_TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)
_NESTING_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)
_MAX_NESTING_DEPTH = 4
_MAX_FUNC_LINES = 80


def _max_nesting(node: ast.AST, depth: int = 0) -> int:
    best = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        next_depth = depth + 1 if isinstance(child, _NESTING_NODES) else depth
        best = max(best, _max_nesting(child, next_depth))
    return best


def _check_unreachable_in_block(
    stmts: list[ast.stmt],
    rel_path: str,
    lines: list[str],
    findings: list[Finding],
) -> None:
    for idx, stmt in enumerate(stmts):
        if isinstance(stmt, _TERMINATORS) and idx < len(stmts) - 1:
            dead = stmts[idx + 1]
            line_no = getattr(dead, "lineno", stmt.lineno)
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append(
                Finding(
                    rule_id="SG008",
                    title="Structural / Code-Quality Slop",
                    severity=Severity.MEDIUM,
                    category="Code Quality",
                    file_path=rel_path,
                    line=line_no,
                    column=getattr(dead, "col_offset", 0) + 1,
                    message="Unreachable code after return/raise/break/continue.",
                    snippet=snippet,
                    suggestion="Remove dead code or fix the control flow.",
                )
            )
            break
        for child_body_attr in ("body", "orelse", "finalbody"):
            sub = getattr(stmt, child_body_attr, None)
            if isinstance(sub, list):
                _check_unreachable_in_block(sub, rel_path, lines, findings)
        if isinstance(stmt, ast.Try):
            for handler in stmt.handlers:
                _check_unreachable_in_block(handler.body, rel_path, lines, findings)


def _check_duplicate_body(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    snippet: str,
    seen_bodies: dict[str, tuple[str, int]],
) -> Finding | None:
    if len(node.body) < 5:
        return None
    body_sig = ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False)
    if body_sig not in seen_bodies:
        seen_bodies[body_sig] = (node.name, node.lineno)
        return None
    orig_name, orig_line = seen_bodies[body_sig]
    return Finding(
        rule_id="SG008",
        title="Structural / Code-Quality Slop",
        severity=Severity.MEDIUM,
        category="Code Quality",
        file_path=rel_path,
        line=node.lineno,
        column=node.col_offset + 1,
        message=f"Function '{node.name}' duplicates the exact body of '{orig_name}' (line {orig_line}).",
        snippet=snippet,
        suggestion=f"Extract shared logic from '{node.name}' and '{orig_name}' into a single helper.",
    )


def _check_function_node(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    lines: list[str],
    seen_bodies: dict[str, tuple[str, int]],
) -> list[Finding]:
    findings: list[Finding] = []
    snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""

    all_defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
    if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in all_defaults):
        findings.append(
            Finding(
                rule_id="SG008",
                title="Structural / Code-Quality Slop",
                severity=Severity.HIGH,
                category="Code Quality",
                file_path=rel_path,
                line=node.lineno,
                column=node.col_offset + 1,
                message=f"Function '{node.name}' uses a mutable default argument ([]/{{}}/set).",
                snippet=snippet,
                suggestion="Use None as the default and initialize inside the function.",
            )
        )

    _check_unreachable_in_block(node.body, rel_path, lines, findings)

    depth = _max_nesting(node)
    if depth > _MAX_NESTING_DEPTH:
        findings.append(
            Finding(
                rule_id="SG008",
                title="Structural / Code-Quality Slop",
                severity=Severity.LOW,
                category="Code Quality",
                file_path=rel_path,
                line=node.lineno,
                column=node.col_offset + 1,
                message=f"Function '{node.name}' has deep nesting ({depth} levels > {_MAX_NESTING_DEPTH}).",
                snippet=snippet,
                suggestion="Use early returns or extract helper functions to flatten control flow.",
            )
        )

    span = getattr(node, "end_lineno", node.lineno) - node.lineno + 1
    if span > _MAX_FUNC_LINES:
        findings.append(
            Finding(
                rule_id="SG008",
                title="Structural / Code-Quality Slop",
                severity=Severity.LOW,
                category="Code Quality",
                file_path=rel_path,
                line=node.lineno,
                column=node.col_offset + 1,
                message=f"Function '{node.name}' is {span} lines long (>{_MAX_FUNC_LINES} lines).",
                snippet=snippet,
                suggestion="Decompose into smaller, single-responsibility functions.",
            )
        )

    dup = _check_duplicate_body(node, rel_path, snippet, seen_bodies)
    if dup:
        findings.append(dup)

    return findings


def detect_code_quality(
    file_path: Path, rel_path: str, content: str, tree: ast.AST | None = None
) -> list[Finding]:
    if file_path.suffix.lower() != ".py":
        return []

    if tree is None:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return []

    lines = content.splitlines()
    seen_bodies: dict[str, tuple[str, int]] = {}
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_check_function_node(node, rel_path, lines, seen_bodies))
    return findings
