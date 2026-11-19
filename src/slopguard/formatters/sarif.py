"""SARIF v2.1.0 formatter for GitHub Code Scanning."""

from __future__ import annotations

import json
from slopguard import __version__
from slopguard.detectors import RULES
from slopguard.models import ScanReport, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def format_sarif(report: ScanReport) -> str:
    rules_list = [
        {
            "id": meta.rule_id,
            "name": meta.title,
            "shortDescription": {"text": meta.title},
            "fullDescription": {"text": meta.description},
            "defaultConfiguration": {"level": _SARIF_LEVEL[meta.default_severity]},
        }
        for meta in RULES.values()
    ]

    results = [
        {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message} {f.suggestion}".strip()},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": f.line, "startColumn": f.column},
                    }
                }
            ],
        }
        for f in report.findings
    ]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SlopGuard",
                        "version": __version__,
                        "rules": rules_list,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
