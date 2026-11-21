"""SG007: Unsafe AI Security Shortcut Detector."""

from __future__ import annotations

import ast
from pathlib import Path

from slopguard.models import Finding, Severity

_SHELL_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
_DANGEROUS_BUILTINS = {"eval", "exec"}


def _check_weak_hash_call(node: ast.Call, rel_path: str, snippet: str) -> Finding | None:
    if not (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"md5", "sha1"}
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "hashlib"
    ):
        return None
    has_flag = any(
        kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False
        for kw in node.keywords
    )
    if has_flag:
        return None
    return Finding(
        rule_id="SG007",
        title="Unsafe AI Security Shortcut",
        severity=Severity.MEDIUM,
        category="Insecure Defaults",
        file_path=rel_path,
        line=node.lineno,
        column=node.col_offset + 1,
        message=f"Weak hash algorithm hashlib.{node.func.attr}() used without usedforsecurity=False.",
        snippet=snippet,
        suggestion="Use hashlib.sha256() (or pass usedforsecurity=False if non-cryptographic).",
    )


def is_unsafe_yaml_load(node: ast.Call) -> bool:
    """yaml.load(x) with no Loader; shared with the --fix rewriter so both agree."""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "load"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "yaml"
        and len(node.args) < 2
        and not any(kw.arg == "Loader" for kw in node.keywords)
    )


def _check_yaml_load_call(node: ast.Call, rel_path: str, snippet: str) -> Finding | None:
    if not is_unsafe_yaml_load(node):
        return None
    return Finding(
        rule_id="SG007",
        title="Unsafe AI Security Shortcut",
        severity=Severity.HIGH,
        category="Insecure Defaults",
        file_path=rel_path,
        line=node.lineno,
        column=node.col_offset + 1,
        message="yaml.load() without SafeLoader can execute arbitrary Python objects.",
        snippet=snippet,
        suggestion="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
    )


def _check_dangerous_exec(node: ast.Call, rel_path: str, snippet: str) -> Finding | None:
    if isinstance(node.func, ast.Name) and node.func.id in _DANGEROUS_BUILTINS:
        return Finding(
            rule_id="SG007",
            title="Unsafe AI Security Shortcut",
            severity=Severity.HIGH,
            category="Insecure Defaults",
            file_path=rel_path,
            line=node.lineno,
            column=node.col_offset + 1,
            message=f"Dynamic code execution via {node.func.id}() risks arbitrary code execution.",
            snippet=snippet,
            suggestion=f"Avoid {node.func.id}() on untrusted input; use ast.literal_eval() or explicit dispatch.",
        )
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        mod, attr = node.func.value.id, node.func.attr
        if (mod == "pickle" and attr in {"load", "loads"}) or (mod == "os" and attr == "system"):
            return Finding(
                rule_id="SG007",
                title="Unsafe AI Security Shortcut",
                severity=Severity.HIGH,
                category="Insecure Defaults",
                file_path=rel_path,
                line=node.lineno,
                column=node.col_offset + 1,
                message=f"Unsafe call {mod}.{attr}() risks arbitrary code/command execution.",
                snippet=snippet,
                suggestion="Use json.loads() instead of pickle, or subprocess.run(..., shell=False) instead of os.system().",
            )
    return None


def _inspect_call_node(node: ast.Call, rel_path: str, snippet: str) -> list[Finding]:
    findings: list[Finding] = []
    for kw in node.keywords:
        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            findings.append(
                Finding(
                    rule_id="SG007",
                    title="Unsafe AI Security Shortcut",
                    severity=Severity.HIGH,
                    category="Insecure Defaults",
                    file_path=rel_path,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    message="TLS certificate verification disabled via verify=False.",
                    snippet=snippet,
                    suggestion="Remove verify=False or pass a valid CA bundle path.",
                )
            )
        elif kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            fn_name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else node.func.id if isinstance(node.func, ast.Name) else ""
            )
            if fn_name in _SHELL_FUNCS:
                findings.append(
                    Finding(
                        rule_id="SG007",
                        title="Unsafe AI Security Shortcut",
                        severity=Severity.HIGH,
                        category="Insecure Defaults",
                        file_path=rel_path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        message=f"subprocess.{fn_name}(..., shell=True) risks command injection.",
                        snippet=snippet,
                        suggestion="Pass an argument list with shell=False (the default).",
                    )
                )
        elif kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
            findings.append(
                Finding(
                    rule_id="SG007",
                    title="Unsafe AI Security Shortcut",
                    severity=Severity.MEDIUM,
                    category="Insecure Defaults",
                    file_path=rel_path,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    message="Binding to 0.0.0.0 exposes the service on all network interfaces.",
                    snippet=snippet,
                    suggestion="Bind to 127.0.0.1 for local development or configure via env var.",
                )
            )

    dangerous = _check_dangerous_exec(node, rel_path, snippet)
    if dangerous:
        findings.append(dangerous)
    unsafe_yaml = _check_yaml_load_call(node, rel_path, snippet)
    if unsafe_yaml:
        findings.append(unsafe_yaml)
    weak_hash = _check_weak_hash_call(node, rel_path, snippet)
    if weak_hash:
        findings.append(weak_hash)
    return findings


def detect_security_shortcuts(
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
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
            findings.extend(_inspect_call_node(node, rel_path, snippet))
    return findings
