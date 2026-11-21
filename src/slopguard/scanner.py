"""Core scanning engine for SlopGuard."""

from __future__ import annotations

import ast
import io
import json
import re
import subprocess
import time
import tokenize
from pathlib import Path

from slopguard.config import SlopGuardConfig, find_project_root, load_config
from slopguard.detectors.api_hallucinations import detect_api_hallucinations
from slopguard.detectors.code_quality import detect_code_quality
from slopguard.detectors.phantom_imports import (
    collect_declared_dependencies,
    collect_local_modules,
    detect_phantom_imports,
)
from slopguard.detectors.prompt_injection import detect_prompt_injection
from slopguard.detectors.registry_check import verify_manifest_dependencies
from slopguard.detectors.secrets import detect_secrets
from slopguard.detectors.security_shortcuts import detect_security_shortcuts
from slopguard.detectors.silent_errors import detect_silent_errors
from slopguard.detectors.stubs import detect_stubs
from slopguard.detectors.test_cheating import detect_test_cheating
from slopguard.models import Finding, ScanReport

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".md", ".txt", ".yml", ".yaml", ".toml", ".json",
}
CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_INLINE_IGNORE_RE = re.compile(r"(?:#|//)\s*slopguard:\s*ignore\b(.*)$", re.IGNORECASE)
_RULE_TOKEN_RE = re.compile(r"\bSG\d{3}\b", re.IGNORECASE)
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _is_line_suppressed(lines: list[str], line_no: int, rule_id: str) -> bool:
    if not (1 <= line_no <= len(lines)):
        return False
    m = _INLINE_IGNORE_RE.search(lines[line_no - 1])
    if not m:
        return False
    tokens = _RULE_TOKEN_RE.findall(m.group(1))
    if not tokens:
        return True
    return rule_id.upper() in {t.upper() for t in tokens}


def _parse_diff_hunks(diff_text: str) -> dict[str, set[int]]:
    changed: dict[str, set[int]] = {}
    current_file: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            changed.setdefault(current_file, set())
            continue
        if line.startswith("+++ /dev/null"):
            current_file = None
            continue
        m = _HUNK_RE.match(line) if (current_file and line.startswith("@@ ")) else None
        if not m:
            continue
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        if count > 0 and current_file:
            changed[current_file].update(range(start, start + count))
    return changed


def _add_untracked_lines(root: Path, changed: dict[str, set[int]]) -> None:
    try:
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return
    if untracked.returncode != 0:
        return
    for rel_file in untracked.stdout.splitlines():
        rel_clean = rel_file.strip()
        fpath = root / rel_clean
        if rel_clean and fpath.is_file():
            line_count = len(fpath.read_text(encoding="utf-8", errors="replace").splitlines())
            changed[rel_clean] = set(range(1, max(2, line_count + 1)))


class GitDiffError(RuntimeError):
    """git diff failed; scanning would otherwise silently report zero findings."""


def _get_git_changed_lines(root: Path, diff_ref: str | None = None, staged: bool = False) -> dict[str, set[int]]:
    """Return {rel_posix_path: {added_or_modified_line_numbers}} from git diff (+ untracked on --diff)."""
    if not staged and not diff_ref:
        return {}
    if not staged and str(diff_ref).startswith("-"):
        raise GitDiffError(f"invalid git ref {diff_ref!r}")
    # --relative: paths relative to the project root even when it is a subdirectory of the git repo.
    cmd = ["git", "diff", "--unified=0", "--no-color", "--no-ext-diff", "--relative", "--src-prefix=a/", "--dst-prefix=b/"]
    cmd += ["--cached"] if staged else [str(diff_ref), "--"]
    try:
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, check=False, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitDiffError(f"could not run git diff: {exc}") from exc
    if proc.returncode != 0:
        raise GitDiffError(proc.stderr.strip() or f"git diff exited with {proc.returncode}")

    changed = _parse_diff_hunks(proc.stdout)
    if not staged and diff_ref:
        _add_untracked_lines(root, changed)
    return changed


def _is_ignored_file(p: Path, target: Path, root: Path, cfg: SlopGuardConfig) -> bool:
    try:
        rel = p.relative_to(root).as_posix()
    except ValueError:
        rel = p.as_posix()
    if target != root and target.is_dir():
        try:
            target_rel = target.relative_to(root).as_posix()
            if cfg.is_ignored(target_rel):
                return cfg.is_ignored(p.relative_to(target).as_posix())
        except ValueError:
            pass
    return cfg.is_ignored(rel) if target.is_dir() else False


def _iter_target_files(target: Path, cfg: SlopGuardConfig, root: Path) -> list[Path]:
    candidates = [target] if target.is_file() else sorted(target.rglob("*"))
    files: list[Path] = []
    for p in candidates:
        if not p.is_file() or p.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        if _is_ignored_file(p, target, root, cfg):
            continue
        try:
            if p.stat().st_size <= cfg.max_file_size_bytes:
                files.append(p)
        except OSError:
            continue
    return files


def _parse_python_once(content: str, rel_path: str) -> tuple[ast.AST | None, list[tuple[int, int, str]]]:
    tree: ast.AST | None = None
    comments: list[tuple[int, int, str]] = []
    try:
        tree = ast.parse(content, filename=rel_path)
    except SyntaxError:
        tree = None
    try:
        for tok in tokenize.generate_tokens(io.StringIO(content).readline):
            if tok.type == tokenize.COMMENT:
                comments.append((tok.start[0], tok.start[1] + 1, tok.string))
    except tokenize.TokenError:
        pass
    return tree, comments


def _scan_single_file(
    fpath: Path,
    rel: str,
    content: str,
    disabled: set[str],
    declared_deps: set[str],
    local_modules: set[str],
) -> list[Finding]:
    suffix = fpath.suffix.lower()
    tree: ast.AST | None = None
    comments: list[tuple[int, int, str]] | None = None
    if suffix == ".py":
        tree, comments = _parse_python_once(content, rel)

    findings: list[Finding] = []
    if "SG006" not in disabled:
        findings.extend(detect_prompt_injection(fpath, rel, content, comments=comments))
    if "SG005" not in disabled:
        findings.extend(detect_secrets(fpath, rel, content))
    if suffix not in CODE_EXTENSIONS:
        return findings

    if "SG001" not in disabled:
        findings.extend(detect_phantom_imports(fpath, rel, content, declared_deps, local_modules, tree=tree))
    if "SG002" not in disabled:
        findings.extend(detect_stubs(fpath, rel, content, tree=tree, comments=comments))
    if "SG003" not in disabled:
        findings.extend(detect_silent_errors(fpath, rel, content, tree=tree))
    if "SG004" not in disabled:
        findings.extend(detect_test_cheating(fpath, rel, content, tree=tree))
    if "SG007" not in disabled:
        findings.extend(detect_security_shortcuts(fpath, rel, content, tree=tree))
    if "SG008" not in disabled:
        findings.extend(detect_code_quality(fpath, rel, content, tree=tree))
    if "SG009" not in disabled:
        findings.extend(detect_api_hallucinations(fpath, rel, content, tree=tree))
    return findings


def _finding_key(f: Finding) -> str:
    return f"{f.rule_id}:{f.file_path}:{f.line}:{f.message}"


def filter_baseline(report: ScanReport, baseline_path: Path) -> ScanReport:
    if not baseline_path.is_file():
        return report
    try:
        known = set(json.loads(baseline_path.read_text(encoding="utf-8")).get("findings", []))
    except (json.JSONDecodeError, OSError):
        return report
    report.findings = [f for f in report.findings if _finding_key(f) not in known]
    return report


def write_baseline(report: ScanReport, baseline_path: Path) -> None:
    keys = sorted({_finding_key(f) for f in report.findings})
    baseline_path.write_text(json.dumps({"findings": keys}, indent=2) + "\n", encoding="utf-8")


def scan_path(
    target_path: str | Path,
    config: SlopGuardConfig | None = None,
    diff_ref: str | None = None,
    staged: bool = False,
    verify_registry: bool = False,
    baseline_path: Path | None = None,
) -> ScanReport:
    t0 = time.perf_counter()
    target = Path(target_path).resolve()
    root = find_project_root(target)
    cfg = config or load_config(root)

    changed_map = _get_git_changed_lines(root, diff_ref=diff_ref, staged=staged) if (staged or diff_ref) else None
    declared_deps = collect_declared_dependencies(root) | cfg.extra_dependencies
    local_modules = collect_local_modules(root)

    all_findings: list[Finding] = []
    if verify_registry and "SG001" not in cfg.disabled_rules:
        all_findings.extend(verify_manifest_dependencies(root, {}))

    scanned_count = 0
    for fpath in _iter_target_files(target, cfg, root):
        rel = fpath.relative_to(root).as_posix() if fpath.is_relative_to(root) else fpath.name
        if changed_map is not None and not changed_map.get(rel):
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        scanned_count += 1
        lines = content.splitlines()
        for finding in _scan_single_file(fpath, rel, content, cfg.disabled_rules, declared_deps, local_modules):
            if changed_map is not None and finding.line not in changed_map.get(rel, set()):
                continue
            if not _is_line_suppressed(lines, finding.line, finding.rule_id):
                all_findings.append(finding)

    all_findings.sort(key=lambda f: (-f.severity.rank, f.file_path, f.line, f.rule_id))
    report = ScanReport(
        target=str(target_path),
        files_scanned=scanned_count,
        duration_ms=(time.perf_counter() - t0) * 1000.0,
        findings=all_findings,
        declared_dependencies=declared_deps,
    )
    return filter_baseline(report, baseline_path) if baseline_path else report
