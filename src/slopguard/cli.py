"""Command-line interface for SlopGuard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from slopguard import __version__
from slopguard.config import load_config
from slopguard.detectors import RULES
from slopguard.formatters import format_json, format_markdown, format_sarif, format_terminal
from slopguard.models import Severity
from slopguard.scanner import scan_path

_CLAUDE_HOOK_MAX_CHARS = 8000

DEFAULT_CONFIG_TEMPLATE = """# SlopGuard configuration
fail-on = "high"

ignore = [
    ".venv/**",
    "node_modules/**",
    "dist/**",
    "build/**",
]

# Disable specific rules if needed:
# disable = ["SG002"]

# Extra packages that are provided at runtime (e.g., AWS Lambda layers):
# extra-dependencies = ["boto3"]
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slopguard",
        description="Catch AI coding slop before it hits main.",
    )
    parser.add_argument("--version", action="version", version=f"slopguard {__version__}")
    sub = parser.add_subparsers(dest="command")

    # check
    p_check = sub.add_parser("check", help="Scan a file or directory for AI coding slop.")
    p_check.add_argument("target", nargs="?", default=".", help="Path to scan (default: current directory).")
    p_check.add_argument(
        "--format",
        choices=["terminal", "json", "sarif", "markdown"],
        default="terminal",
        help="Output format.",
    )
    p_check.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default=None,
        help="Minimum severity that causes a non-zero exit code.",
    )
    p_check.add_argument("--diff", dest="diff_ref", default=None, help="Only report findings on lines changed vs git ref (e.g. origin/main).")
    p_check.add_argument("--staged", action="store_true", help="Only report findings on staged git diff lines.")
    p_check.add_argument("--verify-registry", action="store_true", help="Verify declared PyPI/npm packages against live registries.")
    p_check.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p_check.add_argument("--output", "-o", help="Write output to a file instead of stdout.")

    # rules
    sub.add_parser("rules", help="List all built-in SlopGuard rules.")

    # init
    p_init = sub.add_parser("init", help="Generate a .slopguard.toml config file.")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing .slopguard.toml.")

    # hook
    p_hook = sub.add_parser("hook", help="Run or install AI coding agent hooks (Claude Code PostToolUse).")
    p_hook.add_argument("--claude", action="store_true", help="Read Claude Code hook JSON from stdin.")
    p_hook.add_argument(
        "--install",
        choices=["claude"],
        default=None,
        help="Install SlopGuard PostToolUse hook into .claude/settings.json.",
    )
    p_hook.add_argument(
        "--local",
        action="store_true",
        help="With --install claude, write to .claude/settings.local.json instead of settings.json.",
    )

    return parser


def _find_root(target: Path) -> Path:
    start = target if target.is_dir() else target.parent
    for candidate in [start, *start.parents]:
        if any((candidate / m).exists() for m in ("pyproject.toml", "package.json", "requirements.txt", ".git")):
            return candidate
    return start


def _cmd_check(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"Error: target path '{args.target}' does not exist.", file=sys.stderr)
        return 2

    cfg = load_config(_find_root(target.resolve()))
    report = scan_path(
        target,
        config=cfg,
        diff_ref=args.diff_ref,
        staged=args.staged,
        verify_registry=args.verify_registry,
    )

    if args.format == "terminal":
        out = format_terminal(report, no_color=args.no_color)
    elif args.format == "json":
        out = format_json(report)
    elif args.format == "sarif":
        out = format_sarif(report)
    else:
        out = format_markdown(report)

    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)

    fail_level = args.fail_on or cfg.fail_on.value
    if fail_level == "none":
        return 0
    threshold = Severity(fail_level)
    return 1 if report.has_findings_at_or_above(threshold) else 0


def _cmd_rules() -> int:
    print("SlopGuard Built-in Rules:\n")
    for meta in RULES.values():
        print(f"  {meta.rule_id}  [{meta.default_severity.value.upper():<8}]  {meta.title}")
        print(f"          {meta.description}\n")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    dest = Path(".slopguard.toml")
    if dest.exists() and not args.force:
        print(".slopguard.toml already exists (use --force to overwrite).", file=sys.stderr)
        return 1
    dest.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    print("Created .slopguard.toml")
    return 0


def _install_claude_hook(base_dir: Path | None = None, local: bool = False) -> int:
    root = base_dir or Path.cwd()
    filename = "settings.local.json" if local else "settings.json"
    settings_path = root / ".claude" / filename
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    data: dict = {}
    if settings_path.is_file():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}

    hooks = data.setdefault("hooks", {})
    post_tool = hooks.setdefault("PostToolUse", [])
    hook_entry = {
        "matcher": "Edit|Write",
        "hooks": [{"type": "command", "command": "slopguard hook --claude"}],
    }
    if hook_entry not in post_tool:
        post_tool.append(hook_entry)

    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Installed SlopGuard Claude Code hook in {settings_path}")
    return 0


def _cmd_hook(args: argparse.Namespace) -> int:
    """Claude Code PostToolUse hook: scans edited file and feeds findings back to Claude."""
    if args.install == "claude":
        return _install_claude_hook(local=args.local)

    raw = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    file_path = "."
    if raw:
        try:
            payload = json.loads(raw)
            tool_input = payload.get("tool_input", {})
            file_path = tool_input.get("file_path") or tool_input.get("path") or "."
        except json.JSONDecodeError:
            pass

    target = Path(file_path)
    if not target.exists():
        return 0

    cfg = load_config(_find_root(target.resolve()))
    report = scan_path(target, config=cfg)
    if report.has_findings_at_or_above(cfg.fail_on):
        msg = format_markdown(report)
        if len(msg) > _CLAUDE_HOOK_MAX_CHARS:
            msg = msg[:_CLAUDE_HOOK_MAX_CHARS] + "\n\n...(truncated for Claude Code hook limit)"
        if args.claude:
            print(json.dumps({"decision": "block", "reason": msg}))
            return 0
        print(msg, file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "rules":
        return _cmd_rules()
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "hook":
        return _cmd_hook(args)
    return 0
