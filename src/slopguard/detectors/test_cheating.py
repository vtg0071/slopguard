"""SG004: Test Cheating & Zero-Assertion Test Detector (Python + JS/TS)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from slopguard.models import Finding, Severity

ASSERTION_ATTR_PREFIXES = ("assert", "fail")
ASSERTION_CALL_NAMES = {"assert", "expect", "should", "raises", "warns"}

_JS_TEST_BLOCK_RE = re.compile(
    r"""(?:^|\n)\s*(?:it|test)\s*(?:\.(skip|only))?\s*\(\s*(['"`])(.+?)\2\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{""",
    re.MULTILINE,
)
_JS_ASSERT_RE = re.compile(r"\b(?:expect|assert)\s*\(|\bshould\.")


def _is_test_file(file_path: Path) -> bool:
    name = file_path.name.lower()
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.ts")
        or name.endswith(".test.tsx")
        or name.endswith(".test.js")
        or name.endswith(".test.jsx")
        or name.endswith(".spec.ts")
        or name.endswith(".spec.js")
    )


def _has_assertion(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr.startswith(ASSERTION_ATTR_PREFIXES) or attr in {"raises", "warns", "deprecated_call"}:
                    return True
            elif isinstance(node.func, ast.Name):
                name = node.func.id.lower()
                if name.startswith("assert") or name in ASSERTION_CALL_NAMES:
                    return True
    return False


def _has_unjustified_skip(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        if isinstance(dec, ast.Attribute) and dec.attr == "skip":
            return True
        if isinstance(dec, ast.Call):
            fn = dec.func
            is_skip = (isinstance(fn, ast.Attribute) and fn.attr == "skip") or (
                isinstance(fn, ast.Name) and fn.id == "skip"
            )
            if is_skip:
                has_reason = bool(dec.args) or any(kw.arg == "reason" for kw in dec.keywords)
                if not has_reason:
                    return True
    return False


def _is_tautology_assert(node: ast.Assert) -> bool:
    test = node.test
    if isinstance(test, ast.Constant) and test.value is True:
        return True
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        if isinstance(test.ops[0], ast.Eq):
            left = test.left
            right = test.comparators[0]
            if isinstance(left, ast.Constant) and isinstance(right, ast.Constant) and left.value == right.value:
                return True
    return False


def _extract_brace_block(content: str, open_brace_idx: int) -> str:
    depth = 0
    for idx in range(open_brace_idx, len(content)):
        ch = content[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[open_brace_idx : idx + 1]
    return content[open_brace_idx:]


def detect_test_cheating(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    if not _is_test_file(file_path):
        return findings

    suffix = file_path.suffix.lower()
    lines = content.splitlines()

    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        for m in _JS_TEST_BLOCK_RE.finditer(content):
            modifier = m.group(1)
            test_name = m.group(3)
            line_no = content.count("\n", 0, m.start(3)) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            if modifier == "skip":
                findings.append(
                    Finding(
                        rule_id="SG004",
                        title="Test Cheating / Zero-Assertion Test",
                        severity=Severity.MEDIUM,
                        category="Test Integrity",
                        file_path=rel_path,
                        line=line_no,
                        column=1,
                        message=f"JS/TS test '{test_name}' is skipped via .{modifier}.",
                        snippet=snippet,
                        suggestion=f"Re-enable '{test_name}' or document why it is skipped.",
                    )
                )
            else:
                block = _extract_brace_block(content, m.end() - 1)
                if not _JS_ASSERT_RE.search(block):
                    findings.append(
                        Finding(
                            rule_id="SG004",
                            title="Test Cheating / Zero-Assertion Test",
                            severity=Severity.MEDIUM,
                            category="Test Integrity",
                            file_path=rel_path,
                            line=line_no,
                            column=1,
                            message=f"JS/TS test '{test_name}' executes without any expect()/assert() calls.",
                            snippet=snippet,
                            suggestion=f"Add meaningful assertions verifying behavior in '{test_name}'.",
                        )
                    )
        return findings

    if suffix != ".py":
        return findings

    try:
        tree = ast.parse(content, filename=rel_path)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
            if _has_unjustified_skip(node):
                findings.append(
                    Finding(
                        rule_id="SG004",
                        title="Test Cheating / Zero-Assertion Test",
                        severity=Severity.MEDIUM,
                        category="Test Integrity",
                        file_path=rel_path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        message=f"Test '{node.name}' is skipped without a reason.",
                        snippet=snippet,
                        suggestion=f"Remove @skip or provide an explicit reason=... for '{node.name}'.",
                    )
                )
            elif not _has_assertion(node):
                findings.append(
                    Finding(
                        rule_id="SG004",
                        title="Test Cheating / Zero-Assertion Test",
                        severity=Severity.MEDIUM,
                        category="Test Integrity",
                        file_path=rel_path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        message=f"Test '{node.name}' executes without any assertions.",
                        snippet=snippet,
                        suggestion=f"Add meaningful assertions verifying behavior in '{node.name}'.",
                    )
                )
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assert) and _is_tautology_assert(sub):
                    sub_snip = lines[sub.lineno - 1].strip() if 0 < sub.lineno <= len(lines) else ""
                    findings.append(
                        Finding(
                            rule_id="SG004",
                            title="Test Cheating / Zero-Assertion Test",
                            severity=Severity.HIGH,
                            category="Test Integrity",
                            file_path=rel_path,
                            line=sub.lineno,
                            column=sub.col_offset + 1,
                            message=f"Tautological assertion in '{node.name}' always passes.",
                            snippet=sub_snip,
                            suggestion="Replace tautological assertion with a real behavioral check.",
                        )
                    )

    return findings
