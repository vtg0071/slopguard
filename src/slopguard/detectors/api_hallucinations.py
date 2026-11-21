"""SG009: Hallucinated Stdlib API & Attribute Detector."""

from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path

from slopguard.detectors.phantom_imports import STDLIB_MODULES
from slopguard.models import Finding, Severity

# ponytail: attrs come from the running interpreter, so APIs newer than it are reported; the message names the version.
_PY_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}"
_SAFE_STDLIB_INSPECT = STDLIB_MODULES - {"antigravity", "this", "tty", "pty"}
_MODULE_ATTR_CACHE: dict[str, set[str] | None] = {}


def _get_stdlib_attrs(mod_name: str) -> set[str] | None:
    if mod_name in _MODULE_ATTR_CACHE:
        return _MODULE_ATTR_CACHE[mod_name]
    if mod_name not in _SAFE_STDLIB_INSPECT:
        _MODULE_ATTR_CACHE[mod_name] = None
        return None
    try:
        mod = importlib.import_module(mod_name)
        attrs = set(dir(mod))
    except Exception:  # slopguard: ignore SG003 -- stdlib import may fail on platform-specific modules
        attrs = None
    _MODULE_ATTR_CACHE[mod_name] = attrs
    return attrs


def _is_submodule(mod_name: str, attr: str) -> bool:
    """`logging.handlers` etc. are absent from dir(logging) until imported, but are real."""
    try:
        return importlib.util.find_spec(f"{mod_name}.{attr}") is not None
    except (ImportError, ValueError):
        return False


def _collect_stdlib_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local alias -> stdlib module name (e.g. {'js': 'json', 'os': 'os'})."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "." not in alias.name and alias.name in _SAFE_STDLIB_INSPECT:
                    aliases[alias.asname or alias.name] = alias.name
            continue
        if not (isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in _SAFE_STDLIB_INSPECT):
            continue
        for alias in node.names:
            sub_full = f"{node.module}.{alias.name}"
            if sub_full in _SAFE_STDLIB_INSPECT:
                aliases[alias.asname or alias.name] = sub_full
    return aliases


def detect_api_hallucinations(
    file_path: Path, rel_path: str, content: str, tree: ast.AST | None = None
) -> list[Finding]:
    if file_path.suffix.lower() != ".py":
        return []

    if tree is None:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return []

    aliases = _collect_stdlib_aliases(tree)
    if not aliases:
        return []

    lines = content.splitlines()
    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)):
            continue
        mod_name = aliases.get(node.value.id)
        if not mod_name:
            continue
        attrs = _get_stdlib_attrs(mod_name)
        if attrs is None or node.attr in attrs or node.attr.startswith("_") or _is_submodule(mod_name, node.attr):
            continue
        snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
        findings.append(
            Finding(
                rule_id="SG009",
                title="Hallucinated Stdlib API / Attribute",
                severity=Severity.HIGH,
                category="Slopsquatting & Hallucinations",
                file_path=rel_path,
                line=node.lineno,
                column=node.col_offset + 1,
                message=f"'{mod_name}.{node.attr}' does not exist in Python {_PY_VERSION} stdlib module '{mod_name}'.",
                snippet=snippet,
                suggestion=f"Check the official Python '{mod_name}' docs and replace '{node.attr}' with a valid attribute.",
            )
        )

    return findings
