"""Detector registry and rule metadata for SlopGuard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from slopguard.models import Finding, Severity


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    default_severity: Severity
    category: str
    description: str


RULES: dict[str, RuleMeta] = {
    "SG001": RuleMeta(
        rule_id="SG001",
        title="Phantom / Undeclared Import",
        default_severity=Severity.CRITICAL,
        category="Slopsquatting & Hallucinations",
        description="Import references a package not found in stdlib, local modules, declared dependencies, or live registry (--verify-registry).",
    ),
    "SG002": RuleMeta(
        rule_id="SG002",
        title="Placeholder Stub or Unfinished Code",
        default_severity=Severity.HIGH,
        category="Incomplete Implementation",
        description="Function body is an unimplemented stub (pass, ..., NotImplementedError) or contains TODO/FIXME comments.",
    ),
    "SG003": RuleMeta(
        rule_id="SG003",
        title="Silent Failure / Swallowed Exception",
        default_severity=Severity.HIGH,
        category="Error Handling Anti-Pattern",
        description="Bare except or broad exception handler silently swallows errors without logging or re-raising.",
    ),
    "SG004": RuleMeta(
        rule_id="SG004",
        title="Test Cheating / Zero-Assertion Test",
        default_severity=Severity.MEDIUM,
        category="Test Integrity",
        description="Test function has no assertions, uses tautological assertions (assert True), or skips without reason.",
    ),
    "SG005": RuleMeta(
        rule_id="SG005",
        title="Hardcoded Secret or API Key",
        default_severity=Severity.CRITICAL,
        category="Credential Leak",
        description="Source file contains a hardcoded API key, token, or private key.",
    ),
    "SG006": RuleMeta(
        rule_id="SG006",
        title="Hidden Unicode / Prompt Injection",
        default_severity=Severity.CRITICAL,
        category="Agent & Supply-Chain Security",
        description="File contains Trojan Source bidi overrides, zero-width characters, or agent instruction-hijack comments.",
    ),
    "SG007": RuleMeta(
        rule_id="SG007",
        title="Unsafe AI Security Shortcut",
        default_severity=Severity.HIGH,
        category="Insecure Defaults",
        description="Code disables TLS verification (verify=False), uses shell=True, unsafe yaml.load(), or binds 0.0.0.0.",
    ),    "SG008": RuleMeta(
        rule_id="SG008",
        title="Structural / Code-Quality Slop",
        default_severity=Severity.MEDIUM,
        category="Code Quality",
        description="Detects mutable default arguments, unreachable code, deep nesting, oversized functions, and duplicate function bodies.",
    ),    "SG009": RuleMeta(
        rule_id="SG009",
        title="Hallucinated Stdlib API / Attribute",
        default_severity=Severity.HIGH,
        category="Slopsquatting & Hallucinations",
        description="Detects calls or references to non-existent attributes/methods on Python standard library modules (e.g., json.parse).",
    ),
}

DetectorFn = Callable[..., list[Finding]]
