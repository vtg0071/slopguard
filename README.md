<div align="center">

<img src="assets/banner.png" alt="SlopGuard Banner" width="100%" />

# SlopGuard

**Catch AI coding slop before it hits `main`.**

Zero-dependency CLI, GitHub Action, and Claude Code hook that detects **hallucinated imports (slopsquatting)**, **placeholder stubs**, **silent exception swallowing**, **test cheating**, **leaked secrets**, **hidden prompt injections**, and **unsafe security shortcuts** in `< 60ms` on typical PRs.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-10B981?style=flat-square)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-8B5CF6?style=flat-square)](LICENSE)

</div>

---

## Why This Exists

Peer-reviewed research at [USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen) found that **5.2%** of packages suggested by commercial LLMs and **21.7%** by open-source models did not exist—creating a real supply-chain attack surface (**slopsquatting**). Alongside fake packages, coding agents routinely leave behind `except Exception: pass`, `NotImplementedError` stubs, `verify=False` shortcuts, and zero-assertion tests.

## See It in Action

<div align="center">
  <img src="assets/terminal-demo.svg" alt="SlopGuard Terminal Demo" width="100%" />
</div>

Run it right now on the included demo PR:

```bash
pip install slopguard
slopguard check examples/messy_ai_pr
```

---

## Why SlopGuard?

Traditional linters check formatting and syntax. Security scanners check known CVEs. **Neither catches the failure modes unique to AI-generated code**:

| Failure Mode | `ruff` / `eslint` | `bandit` | `gitleaks` | **SlopGuard** |
| :--- | :---: | :---: | :---: | :---: |
| **Hallucinated / Undeclared Imports** (`slopsquatting` + `--verify-registry`) | — | — | — | **SG001** |
| **Unfinished Stubs** (`pass`, `...`, `NotImplementedError`, `TODO`) | Partial | — | — | **SG002** |
| **Silent Exception Swallowing** (`except Exception: pass`, `catch {}`) | Partial | B110 | — | **SG003** |
| **Test Cheating** (zero assertions, `assert True`, unjustified `@skip`) | — | — | — | **SG004** |
| **Hardcoded AI/Cloud API Keys** (`sk-ant-`, `sk-proj-`, `ghp_`, `AKIA`) | — | — | Yes | **SG005** |
| **Trojan Source Bidi & Agent Prompt Injections** | — | — | — | **SG006** |
| **Unsafe Security Shortcuts** (`verify=False`, `shell=True`, `yaml.load`) | — | Partial | — | **SG007** |
| **Structural Code-Quality Slop** (mutable defaults, dead code, deep nesting, duplicate bodies) | Partial | — | — | **SG008** |
| **Zero-Dependency + Claude Code `PostToolUse` Hook** | — | — | — | **Built-in** |

---

## Architecture

<div align="center">
  <img src="assets/architecture.svg" alt="SlopGuard Architecture" width="100%" />
</div>

---

## Quickstart

### 1. CLI

```bash
# Scan current repository
slopguard check .

# Scan only changed lines in a PR or staged commit
slopguard check --diff origin/main
slopguard check --staged

# Also verify declared PyPI/npm packages against live registries (404 / <30d old)
slopguard check . --verify-registry

# Output JSON, GitHub PR Markdown, or SARIF v2.1.0
slopguard check . --format json
slopguard check . --format markdown
slopguard check . --format sarif -o slopguard.sarif

# Generate .slopguard.toml & list rules
slopguard init
slopguard rules
```

### 2. Claude Code `PostToolUse` Hook (Auto-Block Agent Slop)

Run one command to wire SlopGuard into `.claude/settings.json` (or pass `--local` for `.claude/settings.local.json`):

```bash
slopguard hook --install claude
```

Every time Claude Code edits or writes a file, `slopguard hook --claude` scans it in milliseconds and feeds any issues back to the agent before you even review the diff.

### 3. GitHub Action

```yaml
name: SlopGuard
on: [pull_request]

jobs:
  slopguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: YOUR_USERNAME/slopguard@v0.1.0
        with:
          target: "."
          fail-on: "high"
```

### 4. Pre-Commit Hook

```yaml
repos:
  - repo: https://github.com/YOUR_USERNAME/slopguard
    rev: v0.1.0
    hooks:
      - id: slopguard
```

---

## Inline Suppression

Suppress a specific rule on a single line when intentional:

```python
def abstract_fallback():  # slopguard: ignore SG002
    pass
```

---

## Contributing

Contributions, new language detectors, and rule proposals are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © [SlopGuard Contributors](LICENSE)
