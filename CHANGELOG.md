# Changelog

All notable changes to SlopGuard will be documented in this file.

## [0.1.0] - 2026-11-18

### Added
- Zero-dependency Python 3.10+ CLI (`slopguard check`, `rules`, `init`, `hook`).
- Nine AI-slop & supply-chain detectors (`SG001`–`SG009`): phantom imports, placeholder stubs, silent exception swallowing, test cheating (Python + JS/TS), hardcoded secrets, hidden Unicode / prompt injections, unsafe security shortcuts, structural code-quality slop, and hallucinated stdlib APIs.
- Opt-in live PyPI/npm registry verification (`--verify-registry`) for slopsquatting defense.
- Git diff scoping (`--diff <ref>`, `--staged`) for clean PR/commit gating; a failing `git diff` exits `2` instead of reporting a clean scan.
- `--fix` for safe mechanical fixes (hidden Unicode, `yaml.load` → `yaml.safe_load`) and `--baseline` / `--write-baseline` for adopting on existing codebases.
- One-command Claude Code `PostToolUse` hook installer (`slopguard hook --install claude [--local]`), bundled agent skill (`slopguard skill --install claude|cursor|all`), and a zero-dependency stdio MCP server (`slopguard mcp`).
- Terminal, JSON, Markdown PR comment, and SARIF v2.1.0 formatters, plus `action.yml` and `.pre-commit-hooks.yaml`.
