"""Zero-dependency JSON-RPC 2.0 stdio MCP server for SlopGuard."""

from __future__ import annotations

import json
import sys
from typing import Any

from slopguard import __version__
from slopguard.detectors import RULES
from slopguard.scanner import scan_path

_TOOLS = [
    {
        "name": "slopguard_check",
        "description": "Scan a repository, directory, or git diff for AI coding slop (SG001-SG008) and return a Slop Score + findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "default": "."},
                "diff_ref": {"type": "string"},
                "staged": {"type": "boolean", "default": False},
                "verify_registry": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "slopguard_rules",
        "description": "List all built-in SlopGuard detection rules (SG001-SG008).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def handle_mcp_request(req: dict[str, Any]) -> dict[str, Any] | None:
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}

    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "slopguard", "version": __version__},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "slopguard_rules":
            text = "\n".join(f"{r.rule_id} [{r.default_severity.value}]: {r.title}" for r in RULES.values())
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}}
        if name == "slopguard_check":
            report = scan_path(
                args.get("target", "."),
                diff_ref=args.get("diff_ref"),
                staged=bool(args.get("staged", False)),
                verify_registry=bool(args.get("verify_registry", False)),
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(report.to_dict(), indent=2)}]},
            }
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}}

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def serve_stdio() -> int:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_mcp_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0
