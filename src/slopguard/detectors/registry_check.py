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
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return resp.status, data
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return 0, None


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
        res = ("not_found", None)
    elif status == 200 and isinstance(data, dict):
        age_days: int | None = None
        releases = data.get("releases", {})
        upload_times: list[datetime] = []
        for files in releases.values():
            if isinstance(files, list):
                for f in files:
                    ts = f.get("upload_time_iso_8601")
                    if isinstance(ts, str):
                        try:
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            upload_times.append(dt)
                        except ValueError:
                            pass
        if upload_times:
            earliest = min(upload_times)
            age_days = (datetime.now(timezone.utc) - earliest).days
        if age_days is not None and age_days < _NEW_PACKAGE_DAYS:
            res = ("new", age_days)
        else:
            res = ("ok", age_days)
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
        res = ("not_found", None)
    elif status == 200 and isinstance(data, dict):
        age_days: int | None = None
        created = data.get("time", {}).get("created")
        if isinstance(created, str):
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
            except ValueError:
                pass
        if age_days is not None and age_days < _NEW_PACKAGE_DAYS:
            res = ("new", age_days)
        else:
            res = ("ok", age_days)
    else:
        res = ("error", None)

    cache[key] = res
    return res


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
            if status == "not_found":
                findings.append(
                    Finding(
                        rule_id="SG001",
                        title="Phantom / Undeclared Import",
                        severity=Severity.CRITICAL,
                        category="Slopsquatting & Hallucinations",
                        file_path=rel,
                        line=idx,
                        column=1,
                        message=f"PyPI package '{pkg}' returned 404 Not Found (hallucinated / slopsquatting risk).",
                        snippet=raw.strip(),
                        suggestion=f"Remove '{pkg}' or replace it with a verified PyPI package.",
                    )
                )
            elif status == "new":
                findings.append(
                    Finding(
                        rule_id="SG001",
                        title="Phantom / Undeclared Import",
                        severity=Severity.MEDIUM,
                        category="Slopsquatting & Hallucinations",
                        file_path=rel,
                        line=idx,
                        column=1,
                        message=f"PyPI package '{pkg}' was created only {age_days} day(s) ago (<30d slopsquatting caution).",
                        snippet=raw.strip(),
                        suggestion=f"Verify the maintainer and provenance of '{pkg}' on PyPI before installing.",
                    )
                )

    pkg_json = root / "package.json"
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            for sec in ("dependencies", "devDependencies"):
                if isinstance(data.get(sec), dict):
                    for pkg in data[sec]:
                        status, age_days = verify_npm_package(pkg, cache)
                        if status == "not_found":
                            findings.append(
                                Finding(
                                    rule_id="SG001",
                                    title="Phantom / Undeclared Import",
                                    severity=Severity.CRITICAL,
                                    category="Slopsquatting & Hallucinations",
                                    file_path="package.json",
                                    line=1,
                                    column=1,
                                    message=f"npm package '{pkg}' returned 404 Not Found (hallucinated / slopsquatting risk).",
                                    snippet=f'"{pkg}"',
                                    suggestion=f"Remove '{pkg}' or replace it with a verified npm package.",
                                )
                            )
                        elif status == "new":
                            findings.append(
                                Finding(
                                    rule_id="SG001",
                                    title="Phantom / Undeclared Import",
                                    severity=Severity.MEDIUM,
                                    category="Slopsquatting & Hallucinations",
                                    file_path="package.json",
                                    line=1,
                                    column=1,
                                    message=f"npm package '{pkg}' was created only {age_days} day(s) ago (<30d slopsquatting caution).",
                                    snippet=f'"{pkg}"',
                                    suggestion=f"Verify the maintainer and provenance of '{pkg}' on npm before installing.",
                                )
                            )
        except (json.JSONDecodeError, OSError):
            pass

    return findings
