# Claude Code Launch Instructions for SlopGuard

You are helping the user launch **SlopGuard** to GitHub and PyPI. Execute these steps in order, verifying each step before moving to the next.

## Step 1: Confirm GitHub Handle & Replace Placeholders
1. Ask the user for their GitHub username (or detect it via `gh api user --jq .login` if `gh` is already authenticated).
2. Replace `YOUR_USERNAME` with `<github_username>` in:
   - `README.md`
   - `pyproject.toml`
   - `CONTRIBUTING.md`
3. Run the test suite and self-scan to verify everything passes:
   ```bash
   python3 -m unittest discover -s tests -v
   PYTHONPATH=src python3 -m slopguard check . --fail-on low
   ```
4. Commit the updated URLs:
   ```bash
   git add README.md pyproject.toml CONTRIBUTING.md
   git commit -m "chore: configure repository URLs"
   ```

## Step 2: Create Public GitHub Repo, Topics & Release
1. Verify `gh auth status` (if not logged in, prompt the user to run `gh auth login`).
2. Create and push the public repository:
   ```bash
   gh repo create slopguard --public --source=. --remote=origin --push
   gh repo edit --add-topic ai,linter,security,claude-code,slopsquatting,static-analysis,python,github-actions,mcp
   git tag v0.1.0 && git push origin v0.1.0
   gh release create v0.1.0 --title "v0.1.0 — Catch AI Coding Slop Before It Hits Main" --notes-file CHANGELOG.md
   ```
3. Remind the user to do one quick manual UI step:
   - Open **Settings → Social preview → Edit** on GitHub and upload `assets/banner.png`.
   - Optionally check **"Publish this Action to the GitHub Marketplace"** on the `v0.1.0` release.

## Step 3: Build & Publish to PyPI (Optional / Ask User First)
1. Ask the user if they have a PyPI API token ready.
2. Build and upload:
   ```bash
   python3 -m pip install --upgrade build twine
   python3 -m build
   python3 -m twine upload dist/*
   ```

## Step 4: Generate Ready-to-Post Launch Copy
Run:
```bash
python3 growth/scripts/generate_launch_pack.py \
  --repo "https://github.com/<github_username>/slopguard" \
  --handle "<github_username>"
```
Present the generated **Show HN**, **X/Twitter thread**, and **Reddit** posts to the user, and check `growth/GROWTH_PLAYBOOK.md` for the 100-repo benchmark and Awesome-list PR steps.
