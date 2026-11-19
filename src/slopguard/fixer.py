"""Safe mechanical auto-fixer for SlopGuard (--fix)."""

from __future__ import annotations

import re
from pathlib import Path

from slopguard.config import find_project_root, load_config
from slopguard.detectors.prompt_injection import BIDI_CHARS, ZERO_WIDTH_CHARS
from slopguard.scanner import _iter_target_files

_UNSAFE_YAML_RE = re.compile(r"\byaml\.load\s*\(")
_INVISIBLE_CHARS = BIDI_CHARS | ZERO_WIDTH_CHARS


def fix_path(target_path: str | Path) -> list[tuple[str, str]]:
    """Apply safe mechanical fixes and return [(rel_path, description), ...]."""
    target = Path(target_path).resolve()
    root = find_project_root(target)
    cfg = load_config(root)
    changes: list[tuple[str, str]] = []

    for fpath in _iter_target_files(target, cfg, root):
        try:
            original = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        updated = original
        applied: list[str] = []

        # 1. Strip hidden Trojan Source bidi & zero-width Unicode chars (SG006)
        cleaned = "".join(ch for ch in updated if ch not in _INVISIBLE_CHARS)
        if cleaned != updated:
            updated = cleaned
            applied.append("stripped hidden Unicode control chars (SG006)")

        # 2. Upgrade simple yaml.load(...) -> yaml.safe_load(...) when no Loader= arg (SG007)
        if fpath.suffix.lower() == ".py" and "yaml.load(" in updated and "Loader=" not in updated:
            new_text = _UNSAFE_YAML_RE.sub("yaml.safe_load(", updated)
            if new_text != updated:
                updated = new_text
                applied.append("upgraded yaml.load() to yaml.safe_load() (SG007)")

        if updated != original:
            fpath.write_text(updated, encoding="utf-8")
            rel = fpath.relative_to(root).as_posix() if fpath.is_relative_to(root) else fpath.name
            changes.append((rel, ", ".join(applied)))

    return changes
