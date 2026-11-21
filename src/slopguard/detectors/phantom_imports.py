"""SG001: Phantom / Hallucinated Import Detector (Slopsquatting Guard)."""

from __future__ import annotations

import ast
import importlib.metadata
import json
import re
import sys
from pathlib import Path

from slopguard.config import read_toml
from slopguard.models import Finding, Severity

PYPI_IMPORT_ALIASES: dict[str, set[str]] = {
    "pillow": {"pil"},
    "pyyaml": {"yaml"},
    "beautifulsoup4": {"bs4"},
    "scikit_learn": {"sklearn"},
    "scikit_image": {"skimage"},
    "opencv_python": {"cv2"},
    "opencv_python_headless": {"cv2"},
    "python_dotenv": {"dotenv"},
    "python_dateutil": {"dateutil"},
    "python_jose": {"jose"},
    "python_multipart": {"multipart"},
    "python_docx": {"docx"},
    "pyjwt": {"jwt"},
    "pymupdf": {"fitz"},
    "pyserial": {"serial"},
    "gitpython": {"git"},
    "google_generativeai": {"google"},
    "google_genai": {"google"},
    "google_cloud_storage": {"google"},
    "google_api_python_client": {"googleapiclient"},
    "protobuf": {"google"},
    "attrs": {"attr"},
    "msgpack": {"msgpack"},
    "pycryptodome": {"crypto"},
    "pycryptodomex": {"cryptodome"},
    "pyopenssl": {"openssl"},
    "psycopg2_binary": {"psycopg2"},
    "mysqlclient": {"mysqldb"},
    "pydantic_settings": {"pydantic_settings"},
    "typing_extensions": {"typing_extensions"},
}

NODE_BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events",
    "fs", "http", "http2", "https", "inspector", "module", "net", "os",
    "path", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events",
    "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
}

STDLIB_MODULES: set[str] = set(getattr(sys, "stdlib_module_names", set())) | {
    "__future__", "builtins", "typing", "dataclasses", "pathlib", "json",
    "re", "os", "sys", "math", "time", "datetime", "collections", "itertools",
    "functools", "unittest", "argparse", "subprocess", "hashlib", "hmac",
    "base64", "enum", "abc", "io", "logging", "shutil", "tempfile", "fnmatch",
    "tomllib", "ast", "urllib", "http", "email", "csv", "sqlite3", "asyncio",
}

_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+.*?\s+from\s+|import\s+|require\s*\(\s*)['"]([^'"]+)['"]"""
)


def _normalize_pkg(name: str) -> str:
    return re.split(r"[<>=!~\[;@\s]", name.strip(), maxsplit=1)[0].lower().replace("-", "_")


def _installed_dist_to_imports() -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    try:
        for import_name, dists in importlib.metadata.packages_distributions().items():
            for dist in dists:
                mapping.setdefault(_normalize_pkg(dist), set()).add(import_name.lower())
    except (OSError, AttributeError):
        pass
    return mapping


def _add_pkg_with_aliases(raw_name: str, deps: set[str], dist_map: dict[str, set[str]]) -> None:
    pkg = _normalize_pkg(raw_name)
    if pkg and pkg != "python":
        deps.add(pkg)
        deps.update(PYPI_IMPORT_ALIASES.get(pkg, set()))
        deps.update(dist_map.get(pkg, set()))


def _collect_pyproject_deps(pyproject: Path, deps: set[str], dist_map: dict[str, set[str]]) -> None:
    if not pyproject.is_file():
        return
    try:
        data = read_toml(pyproject)
    except (ValueError, OSError, UnicodeDecodeError):
        return

    all_raw = list(data.get("project", {}).get("dependencies", []))
    for grp in data.get("project", {}).get("optional-dependencies", {}).values():
        if isinstance(grp, list):
            all_raw.extend(grp)
    for grp in data.get("dependency-groups", {}).values():
        if isinstance(grp, list):
            all_raw.extend(x for x in grp if isinstance(x, str))
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        all_raw.extend(poetry_deps.keys())
    for item in all_raw:
        _add_pkg_with_aliases(str(item), deps, dist_map)


def _collect_package_json_deps(pkg_json: Path, deps: set[str]) -> None:
    if not pkg_json.is_file():
        return
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return
    for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        sec_val = data.get(sec)
        if isinstance(sec_val, dict):
            deps.update(k.lower() for k in sec_val)


def collect_declared_dependencies(root: Path) -> set[str]:
    """Collect declared Python and JS/TS package names from project manifests."""
    deps: set[str] = set()
    dist_map = _installed_dist_to_imports()

    for req_file in root.glob("requirements*.txt"):
        if not req_file.is_file():
            continue
        for raw in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line and not line.startswith("-"):
                _add_pkg_with_aliases(line, deps, dist_map)

    _collect_pyproject_deps(root / "pyproject.toml", deps, dist_map)
    _collect_package_json_deps(root / "package.json", deps)
    return deps


def collect_local_modules(root: Path) -> set[str]:
    """Discover local top-level Python modules and packages in the repo."""
    local: set[str] = set()
    search_roots = [root]
    for sub in ("src", "tests"):
        if (root / sub).is_dir():
            search_roots.append(root / sub)

    for base in search_roots:
        for entry in base.iterdir():
            if entry.name.startswith("."):
                continue
            if entry.is_file() and entry.suffix == ".py":
                local.add(entry.stem.lower())
            elif entry.is_dir() and ((entry / "__init__.py").is_file() or any(entry.glob("*.py"))):
                local.add(entry.name.lower())
    return local


def _has_nearest_package_json(file_path: Path) -> bool:
    return any((parent / "package.json").is_file() for parent in [file_path.parent, *file_path.parent.parents])


def _is_type_checking_guard(node: ast.If) -> bool:
    test = node.test
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _collect_guarded_import_lines(tree: ast.AST) -> set[int]:
    guarded: set[int] = set()
    for node in ast.walk(tree):
        is_import_try = isinstance(node, ast.Try) and any(
            (isinstance(h.type, ast.Name) and h.type.id in {"ImportError", "ModuleNotFoundError"})
            or (
                isinstance(h.type, ast.Tuple)
                and any(isinstance(el, ast.Name) and el.id in {"ImportError", "ModuleNotFoundError"} for el in h.type.elts)
            )
            for h in node.handlers
        )
        if is_import_try or (isinstance(node, ast.If) and _is_type_checking_guard(node)):
            guarded.update(
                sub.lineno for sub in ast.walk(node) if isinstance(sub, (ast.Import, ast.ImportFrom))
            )
    return guarded


def _is_known_python_module(top: str, declared_deps: set[str], local_modules: set[str]) -> bool:
    norm = top.lower().replace("-", "_")
    return (
        top in STDLIB_MODULES
        or norm in STDLIB_MODULES
        or norm in local_modules
        or top in local_modules
        or norm in declared_deps
        or top in declared_deps
    )


def _is_sibling_module(file_path: Path, name: str) -> bool:
    """Python puts a script's own directory on sys.path, so `import helpers` beside helpers.py is local."""
    parent = file_path.parent
    return (parent / f"{name}.py").is_file() or (parent / name / "__init__.py").is_file()


def _scan_python_imports(
    file_path: Path,
    rel_path: str,
    content: str,
    declared_deps: set[str],
    local_modules: set[str],
    tree: ast.AST | None,
) -> list[Finding]:
    if tree is None:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return []

    findings: list[Finding] = []
    guarded_lines = _collect_guarded_import_lines(tree)
    lines = content.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and node.lineno not in guarded_lines:
            for alias in node.names:
                top = alias.name.split(".", 1)[0].lower()
                if not _is_known_python_module(top, declared_deps, local_modules) and not _is_sibling_module(
                    file_path, alias.name.split(".", 1)[0]
                ):
                    snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
                    findings.append(
                        Finding(
                            rule_id="SG001",
                            title="Phantom / Undeclared Import",
                            severity=Severity.CRITICAL,
                            category="Slopsquatting & Hallucinations",
                            file_path=rel_path,
                            line=node.lineno,
                            column=node.col_offset + 1,
                            message=f"Module '{alias.name}' is not in Python stdlib, local repo, or declared dependencies.",
                            snippet=snippet,
                            suggestion=f"Verify '{top}' is a real package (not AI-hallucinated) and add it to pyproject.toml/requirements.txt, or remove the import.",
                        )
                    )
        elif isinstance(node, ast.ImportFrom) and node.lineno not in guarded_lines and node.level == 0 and node.module:
            top = node.module.split(".", 1)[0].lower()
            if not _is_known_python_module(top, declared_deps, local_modules) and not _is_sibling_module(
                file_path, node.module.split(".", 1)[0]
            ):
                snippet = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else ""
                findings.append(
                    Finding(
                        rule_id="SG001",
                        title="Phantom / Undeclared Import",
                        severity=Severity.CRITICAL,
                        category="Slopsquatting & Hallucinations",
                        file_path=rel_path,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        message=f"Module '{node.module}' is not in Python stdlib, local repo, or declared dependencies.",
                        snippet=snippet,
                        suggestion=f"Verify '{top}' is a real package (not AI-hallucinated) and add it to pyproject.toml/requirements.txt.",
                    )
                )
    return findings


def _scan_js_imports(
    file_path: Path, rel_path: str, content: str, declared_deps: set[str]
) -> list[Finding]:
    if not _has_nearest_package_json(file_path):
        return []
    findings: list[Finding] = []
    for idx, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for m in _JS_IMPORT_RE.finditer(line):
            spec = m.group(1)
            if spec.startswith((".", "/", "@/", "~/", "node:")):
                continue
            pkg = spec.split("/")[0] if not spec.startswith("@") else "/".join(spec.split("/")[:2])
            if pkg.lower() in NODE_BUILTINS or pkg.lower() in declared_deps:
                continue
            findings.append(
                Finding(
                    rule_id="SG001",
                    title="Phantom / Undeclared Import",
                    severity=Severity.CRITICAL,
                    category="Slopsquatting & Hallucinations",
                    file_path=rel_path,
                    line=idx,
                    column=m.start(1) + 1,
                    message=f"Package '{pkg}' is not declared in package.json or Node built-ins.",
                    snippet=stripped,
                    suggestion=f"Verify '{pkg}' exists on npm and add it to package.json.",
                )
            )
    return findings


def detect_phantom_imports(
    file_path: Path,
    rel_path: str,
    content: str,
    declared_deps: set[str],
    local_modules: set[str],
    tree: ast.AST | None = None,
) -> list[Finding]:
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return _scan_python_imports(file_path, rel_path, content, declared_deps, local_modules, tree)
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return _scan_js_imports(file_path, rel_path, content, declared_deps)
    return []
