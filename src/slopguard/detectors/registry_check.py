"""Opt-in live PyPI & npm registry verification for Slopsquatting defense."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from slopguard.models import Finding, Severity

_NEW_PACKAGE_DAYS = 30


def _query_json(url: str, timeout: float = 3.0) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"User-Agent": "SlopGuard/0.1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return 0, None


def _earliest_pypi_upload(data: dict) -> datetime | None:
    upload_times: list[datetime] = []
    for files in data.get("releases", {}).values():
        if not isinstance(files, list):
            continue
        for f in files:
            ts = f.get("upload_time_iso_8601") if isinstance(f, dict) else None
            if isinstance(ts, str):
                try:
                    upload_times.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except ValueError:
                    pass
    return min(upload_times) if upload_times else None


def verify_pypi_package(
    pkg: str,
    cache: dict[str, tuple[str, int | None]],
) -> tuple[str, int | None]:
    """Return ('ok'|'not_found'|'new'|'error', age_days)."""
    key = f"pypi:{pkg.lower()}"
    if key in cache:
        return cache[key]

    status, data = _query_json(f"https://pypi.org/pypi/{pkg}/json")
    if status == 404:
        res: tuple[str, int | None] = ("not_found", None)
    elif status == 200 and isinstance(data, dict):
        earliest = _earliest_pypi_upload(data)
        age_days = (datetime.now(timezone.utc) - earliest).days if earliest else None
        res = ("new", age_days) if (age_days is not None and age_days < _NEW_PACKAGE_DAYS) else ("ok", age_days)
    else:
        res = ("error", None)

    cache[key] = res
    return res


def verify_npm_package(
    pkg: str,
    cache: dict[str, tuple[str, int | None]],
) -> tuple[str, int | None]:
    """Return ('ok'|'not_found'|'new'|'error', age_days)."""
    key = f"npm:{pkg.lower()}"
    if key in cache:
        return cache[key]

    status, data = _query_json(f"https://registry.npmjs.org/{pkg}")
    if status == 404:
        res: tuple[str, int | None] = ("not_found", None)
    elif status == 200 and isinstance(data, dict):
        created = data.get("time", {}).get("created")
        age_days: int | None = None
        if isinstance(created, str):
            try:
                age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
            except ValueError:
                pass
        res = ("new", age_days) if (age_days is not None and age_days < _NEW_PACKAGE_DAYS) else ("ok", age_days)
    else:
        res = ("error", None)

    cache[key] = res
    return res


def _registry_finding(
    ecosystem: str,
    pkg: str,
    status: str,
    age_days: int | None,
    rel_path: str,
    line: int,
    snippet: str,
) -> Finding | None:
    if status == "not_found":
        return Finding(
            rule_id="SG001",
            title="Phantom / Undeclared Import",
            severity=Severity.CRITICAL,
            category="Slopsquatting & Hallucinations",
            file_path=rel_path,
            line=line,
            column=1,
            message=f"{ecosystem} package '{pkg}' returned 404 Not Found (hallucinated / slopsquatting risk).",
            snippet=snippet,
            suggestion=f"Remove '{pkg}' or replace it with a verified {ecosystem} package.",
        )
    if status == "new":
        return Finding(
            rule_id="SG001",
            title="Phantom / Undeclared Import",
            severity=Severity.MEDIUM,
            category="Slopsquatting & Hallucinations",
            file_path=rel_path,
            line=line,
            column=1,
            message=f"{ecosystem} package '{pkg}' was created only {age_days} day(s) ago (<30d slopsquatting caution).",
            snippet=snippet,
            suggestion=f"Verify the maintainer and provenance of '{pkg}' on {ecosystem} before installing.",
        )
    return None


def verify_manifest_dependencies(root: Path, cache: dict[str, tuple[str, int | None]]) -> list[Finding]:
    """Verify declared packages in requirements*.txt and package.json against live registries."""
    findings: list[Finding] = []

    for req_file in sorted(root.glob("requirements*.txt")):
        if not req_file.is_file():
            continue
        rel = req_file.relative_to(root).as_posix()
        for idx, raw in enumerate(req_file.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            pkg = line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].split("[")[0].strip()
            if not pkg:
                continue
            status, age_days = verify_pypi_package(pkg, cache)
            finding = _registry_finding("PyPI", pkg, status, age_days, rel, idx, raw.strip())
            if finding:
                findings.append(finding)

    pkg_json = root / "package.json"
    if not pkg_json.is_file():
        return findings

    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return findings

    for sec in ("dependencies", "devDependencies"):
        sec_val = data.get(sec)
        if not isinstance(sec_val, dict):
            continue
        for pkg in sec_val:
            status, age_days = verify_npm_package(pkg, cache)
            finding = _registry_finding("npm", pkg, status, age_days, "package.json", 1, f'"{pkg}"')
            if finding:
                findings.append(finding)

    return findings
