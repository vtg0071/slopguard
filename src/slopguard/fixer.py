"""Safe mechanical auto-fixer for SlopGuard (--fix)."""

from __future__ import annotations

import ast
from pathlib import Path

from slopguard.config import find_project_root, load_config
from slopguard.detectors.prompt_injection import BIDI_CHARS, HIDDEN_ZERO_WIDTH_RE
from slopguard.detectors.security_shortcuts import is_unsafe_yaml_load
from slopguard.scanner import _iter_target_files


def _strip_hidden_unicode(text: str) -> str:
    return HIDDEN_ZERO_WIDTH_RE.sub("", "".join(ch for ch in text if ch not in BIDI_CHARS))


def _upgrade_yaml_load(text: str) -> str:
    """Rewrite exactly the yaml.load() calls SG007 flags; leave Loader=/positional-Loader calls alone."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    hits = {(n.lineno, n.func.value.col_offset) for n in ast.walk(tree) if isinstance(n, ast.Call) and is_unsafe_yaml_load(n)}
    if not hits:
        return text
    lines = text.splitlines(keepends=True)
    for lineno, col in hits:
        raw = lines[lineno - 1].encode("utf-8")  # col_offset is a UTF-8 byte offset
        if raw[col:].startswith(b"yaml.load"):
            lines[lineno - 1] = (raw[:col] + b"yaml.safe_load" + raw[col + len(b"yaml.load"):]).decode("utf-8")
    return "".join(lines)


def fix_path(target_path: str | Path) -> list[tuple[str, str]]:
    """Apply safe mechanical fixes and return [(rel_path, description), ...]."""
    target = Path(target_path).resolve()
    root = find_project_root(target)
    cfg = load_config(root)
    changes: list[tuple[str, str]] = []

    for fpath in _iter_target_files(target, cfg, root):
        try:
            # Bytes in/out keeps CRLF line endings; non-UTF-8 files are skipped rather than rewritten lossily.
            original = fpath.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        updated = original
        applied: list[str] = []

        cleaned = _strip_hidden_unicode(updated)
        if cleaned != updated:
            updated = cleaned
            applied.append("stripped hidden Unicode control chars (SG006)")

        if fpath.suffix.lower() == ".py":
            new_text = _upgrade_yaml_load(updated)
            if new_text != updated:
                updated = new_text
                applied.append("upgraded yaml.load() to yaml.safe_load() (SG007)")

        if updated != original:
            fpath.write_bytes(updated.encode("utf-8"))
            rel = fpath.relative_to(root).as_posix() if fpath.is_relative_to(root) else fpath.name
            changes.append((rel, ", ".join(applied)))

    return changes
