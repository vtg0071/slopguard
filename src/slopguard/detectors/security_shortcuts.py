"""SG007: Unsafe AI Security Shortcut Detector."""

from __future__ import annotations

import ast
from pathlib import Path

from slopguard.models import Finding, Severity

_SHELL_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}


def detect_security_shortcuts(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    if file_path.suffix.lower() != ".py":
        return findings

    try:
        tree = ast.parse(content, filename=rel_path)
    except SyntaxError:
        return findings

    lines = content.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
            # 1. verify=False in HTTP calls
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
                # 2. subprocess(..., shell=True)
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    fn_name = ""
                    if isinstance(node.func, ast.Attribute):
                        fn_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        fn_name = node.func.id
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
                # 3. host="0.0.0.0"
                if kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
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

            # 4. yaml.load(...) without Loader
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "load"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "yaml"
            ):
                has_loader = any(kw.arg == "Loader" for kw in node.keywords) or len(node.args) >= 2
                if not has_loader:
                    findings.append(
                        Finding(
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
                    )

    return findings
