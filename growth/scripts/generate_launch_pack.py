"""Generate ready-to-post launch copy & gh CLI commands for SlopGuard."""

from __future__ import annotations

import argparse


def generate_pack(repo_url: str, handle: str) -> str:
    return f"""# SlopGuard Launch Pack ({repo_url})

## 1. Show HN Post
Title: Show HN: SlopGuard – Catch hallucinated imports and AI coding slop in <60ms (zero deps)

Body:
Hey HN,

I built SlopGuard ({repo_url}) after reviewing too many AI-assisted PRs that looked clean at a glance but contained hallucinated PyPI/npm imports (slopsquatting risk), `except Exception: pass`, `NotImplementedError` stubs, or tests with zero assertions.

Existing linters (ruff, eslint) check style, and secret scanners check keys, so SlopGuard focuses specifically on AI-coding failure modes:
- SG001: Phantom / undeclared imports (checks Python stdlib + pyproject/requirements/package.json + local modules)
- SG002: Unimplemented stubs & leftover TODO/FIXME markers
- SG003: Silent failure / swallowed exceptions
- SG004: Test cheating (zero-assertion tests, `assert True`)
- SG005: Hardcoded AI & cloud API keys
- SG006: Trojan Source bidi Unicode & agent prompt injections

It's pure Python 3.10+ with zero external dependencies, outputs terminal/JSON/SARIF/PR-Markdown, and ships with a GitHub Action + a `PostToolUse` hook for Claude Code (`slopguard hook --claude`).

Try it on the included demo:
  pip install slopguard
  slopguard check examples/messy_ai_pr

Feedback and new rule ideas are very welcome!

---

## 2. X / Twitter Thread
Post 1/4:
AI coding agents are fast—until they hallucinate a fake PyPI package, swallow an exception with `except: pass`, or write `assert True` to pass your test suite.

Meet SlopGuard: a zero-dependency CLI & Claude Code hook that catches AI coding slop in <60ms.
{repo_url}

Post 2/4:
What it catches out of the box:
• Phantom imports (slopsquatting guard)
• Stubs & `NotImplementedError`
• Silent `except Exception: pass`
• Zero-assertion / `assert True` tests
• Hardcoded OpenAI/Anthropic/AWS/Stripe keys
• Hidden Unicode & prompt injections

Post 3/4:
My favorite feature: wire it directly into Claude Code's `PostToolUse` hook (`slopguard hook --claude`).
Every time Claude edits a file, SlopGuard scans it in milliseconds and feeds any issues straight back to the agent before you even see the diff.

Post 4/4:
Zero dependencies. MIT licensed. Ships with SARIF + GitHub Action + pre-commit hook.
Star & try it on your repo:
`pip install slopguard && slopguard check .`
{repo_url}

---

## 3. Automated GitHub CLI Setup Commands
gh repo create slopguard --public --source=. --remote=origin --push
gh repo edit {handle}/slopguard --add-topic ai,linter,security,claude-code,slopsquatting,static-analysis,python,github-actions,sarif
git tag v0.1.0 && git push origin v0.1.0
gh release create v0.1.0 --title "v0.1.0" --notes "Initial release of SlopGuard."
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate SlopGuard launch pack.")
    parser.add_argument("--repo", default="https://github.com/YOUR_USERNAME/slopguard")
    parser.add_argument("--handle", default="YOUR_USERNAME")
    args = parser.parse_args()
    print(generate_pack(args.repo, args.handle))


if __name__ == "__main__":
    main()
