"""Zero-dependency JSON-RPC 2.0 stdio MCP server for SlopGuard."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from slopguard import __version__
from slopguard.detectors import RULES
from slopguard.scanner import scan_path

_TOOLS = [
    {
        "name": "slopguard_check",
        "description": "Scan a repository, directory, or git diff for AI coding slop (SG001-SG009) and return a Slop Score + findings.",
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
        "description": "List all built-in SlopGuard detection rules (SG001-SG009).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def handle_mcp_request(req: dict[str, Any]) -> dict[str, Any] | None:
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}

    if "id" not in req:  # JSON-RPC notification: never answered
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
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
            target = str(args.get("target", "."))
            try:
                if not Path(target).exists():
                    raise FileNotFoundError(f"target path '{target}' does not exist")
                report = scan_path(
                    target,
                    diff_ref=args.get("diff_ref"),
                    staged=bool(args.get("staged", False)),
                    verify_registry=bool(args.get("verify_registry", False)),
                )
            except Exception as exc:  # any scan failure goes back to the client as a tool error
                text, is_error = f"slopguard_check failed: {exc}", True
            else:
                text, is_error = json.dumps(report.to_dict(), indent=2), False
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": is_error},
            }
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"Unknown tool: {name}"}}

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
        if not isinstance(req, dict):
            continue
        resp = handle_mcp_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0
