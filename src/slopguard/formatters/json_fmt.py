"""JSON output formatter."""

from __future__ import annotations

import json
from slopguard.models import ScanReport


def format_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)
