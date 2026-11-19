# Changelog

All notable changes to SlopGuard will be documented in this file.

## [0.1.0] - 2026-11-18

### Added
- Zero-dependency Python 3.10+ CLI (`slopguard check`, `rules`, `init`, `hook`).
- Seven AI-slop & supply-chain detectors (`SG001`–`SG007`): phantom imports, placeholder stubs, silent exception swallowing, test cheating (Python + JS/TS), hardcoded secrets, hidden Unicode / prompt injections, and unsafe security shortcuts.
- Opt-in live PyPI/npm registry verification (`--verify-registry`) for slopsquatting defense.
- Git diff scoping (`--diff <ref>`, `--staged`) for clean PR/commit gating.
- One-command Claude Code `PostToolUse` hook installer (`slopguard hook --install claude [--local]`).
- Terminal, JSON, Markdown PR comment, and SARIF v2.1.0 formatters, plus `action.yml` and `.pre-commit-hooks.yaml`.
