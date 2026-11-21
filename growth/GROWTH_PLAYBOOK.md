# SlopGuard Automated Growth Playbook (0 -> 5,000+ Stars)

This playbook is structured so **Claude Code** (or any agent with `gh`, `git`, browser, or cron access) can automate 80%+ of the launch, distribution, and star-compounding loop.

---

## 1. Core Viral Mechanics Built Into the Repo
1. **Instant "Aha!" Demo (`examples/messy_ai_pr`)**: Anyone cloning or installing runs one command and immediately sees a `100/100 Grade F` catch of a hallucinated PyPI package (`fast_yaml_magic`), a prompt injection, and `assert True` test cheating in `1.1ms`.
2. **Zero-Dependency + <60ms Speed**: No `pip` dependency hell, no LLM API key required.
3. **Built-in Agent Hook (`slopguard hook --claude`)**: Rides the massive wave of Claude Code / Cursor / Codex power users who share `.claude/settings.json` snippets on X and Reddit.
4. **Built-in Badge Loop**: Teams add `Protected by SlopGuard` or the GitHub Action PR comment (`## 🚨 SlopGuard Report — Grade F`), exposing every contributor and reviewer to the repo.

---

## 2. Automated Pre-Launch Checklist (Run with `gh` CLI + Claude Code)

```bash
# 1. Create public GitHub repo & push
gh repo create slopguard --public --source=. --remote=origin --push

# 2. Set viral GitHub Topics for discoverability
gh repo edit --add-topic ai,linter,security,claude-code,slopsquatting,static-analysis,python,github-actions,sarif

# 3. Tag v0.1.0 release (triggers PyPI / GitHub Marketplace visibility)
git tag v0.1.0 && git push origin v0.1.0
gh release create v0.1.0 --title "v0.1.0 — Catch AI Coding Slop Before It Hits Main" --notes-file README.md
```

**Manual 30-second step in GitHub UI**: Upload `assets/banner.png` under **Settings -> Social preview** so every X, LinkedIn, Slack, and Discord link unfurls with the dark-mode 1280x640 card.

---

## 3. Automated Growth Engine #1: The "State of AI Slop" Benchmark (Highest-ROI Star Driver)
Developer tools go viral on Hacker News and X when backed by **original empirical data**.

**Automate with Claude Code / Cron**:
1. Use `gh search repos --sort stars --created >2025-01-01 --limit 100` to clone 100 recent open-source Python/JS repos.
2. Run `slopguard check <repo> --format json` across all 100 repos locally in <10 seconds.
3. Aggregate anonymized statistics (never name-and-shame individual repos):
   - *"% of repos with undeclared/phantom imports"*
   - *"% of repos with swallowed `except Exception: pass` blocks"*
   - *"% of test suites with zero-assertion tests"*
4. Publish a short blog post / README section / X thread: **"We scanned 100 vibe-coded GitHub repos with a zero-dependency AST scanner. Here's what we found."**

---

## 4. Automated Growth Engine #2: Launch Day Multi-Channel Sequence
Run `python3 growth/scripts/generate_launch_pack.py --repo https://github.com/YOUR_USERNAME/slopguard` to generate ready-to-post copy for:

| Channel | Timing (PT) | Angle |
| :--- | :--- | :--- |
| **Hacker News (Show HN)** | Tue/Wed 08:30 AM | Technical deep-dive: AST + stdlib/manifest graph to catch slopsquatting & test cheating in <60ms with zero deps |
| **X / Twitter Thread** | Tue/Wed 09:00 AM | 4-post thread with `terminal-demo.svg` (converted to PNG/GIF) + Claude Code `PostToolUse` hook snippet |
| **Reddit (`r/ClaudeAI`, `r/Python`, `r/LocalLLaMA`)** | Wed/Thu | "I built a Claude Code PostToolUse hook that auto-blocks hallucinated imports & `except: pass` before I even review the diff" |
| **Awesome Lists PRs** | Week 1 | Automated PRs to `awesome-claude-code`, `awesome-python`, `awesome-static-analysis`, `awesome-devsecops` |

---

## 5. Automated Growth Engine #3: Ongoing Claude Code Maintenance & Star Loop
1. **Automated Rule-Request Triage**: Set up a GitHub Actions workflow triggered on `issues` labeled `new-rule` that invokes Claude Code to scaffold the detector in `src/slopguard/detectors/`, add unit tests, and open a draft PR.
2. **Weekly Changelog & Release Bot**: Every Friday, summarize merged PRs and star milestones into a release note and X post.
3. **Ecosystem Integrations**: Publish to PyPI (`twine upload dist/*`) and submit to GitHub Marketplace (`action.yml` is already Marketplace-ready!).


---

## 6. High-Leverage Viral Distribution Upgrades (Zero-Following Playbook)
1. **Zero-Install Browser Tryout (`slopguard.dev/owner/repo`):** Following `gitingest` and `GitDiagram`, let any developer swap `github.com` in a repo URL to get an instant **Slop Score Card + copyable `Protected by SlopGuard` README badge** in 3 seconds with zero `pip install`.
2. **PR Auto-Comment Loop (`action.yml`):** Enable `comment-pr: true` (now built into `action.yml`) so every pull request gets an automatic `SlopGuard Report — Grade` comment linking back to the repo.
3. **5-Second Animated Terminal GIF/MP4:** Record a crisp 5-second video showing Claude Code writing a hallucinated import and `slopguard hook --claude` blocking it in real time for X/Twitter, Reddit (`r/ClaudeAI`, `r/Python`), and Product Hunt.
4. **Lead Launch Posts With the 100-Repo Benchmark:** Run `slopguard check --format json` across 100 recent AI-built repos locally and lead Show HN with empirical percentages rather than a generic tool announcement.
5. **Pre-Launch Plumbing:** Replace `YOUR_USERNAME` in `README.md`, `pyproject.toml`, and `CONTRIBUTING.md`, publish `v0.1.0` to PyPI (`python -m build && twine upload dist/*`), and upload `assets/banner.png` under **Settings -> Social preview**.
