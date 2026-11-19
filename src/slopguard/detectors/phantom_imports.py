"""SG001: Phantom / Hallucinated Import Detector (Slopsquatting Guard)."""

from __future__ import annotations

import ast
import importlib.metadata
import json
import re
import sys
from pathlib import Path

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
        pkg_dists = importlib.metadata.packages_distributions()
        for import_name, dists in pkg_dists.items():
            for dist in dists:
                mapping.setdefault(_normalize_pkg(dist), set()).add(import_name.lower())
    except (OSError, AttributeError):
        pass
    return mapping


def collect_declared_dependencies(root: Path) -> set[str]:
    """Collect declared Python and JS/TS package names from project manifests."""
    deps: set[str] = set()
    dist_map = _installed_dist_to_imports()

    def _add_pkg(raw_name: str) -> None:
        pkg = _normalize_pkg(raw_name)
        if pkg and pkg != "python":
            deps.add(pkg)
            deps.update(PYPI_IMPORT_ALIASES.get(pkg, set()))
            deps.update(dist_map.get(pkg, set()))

    for req_file in root.glob("requirements*.txt"):
        if req_file.is_file():
            for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                _add_pkg(line)

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8", errors="ignore")
        try:
            import tomllib  # Python 3.11+
            data = tomllib.loads(text)
            proj_deps = data.get("project", {}).get("dependencies", [])
            opt_deps = data.get("project", {}).get("optional-dependencies", {})
            dep_groups = data.get("dependency-groups", {})
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            all_raw = list(proj_deps)
            for grp in opt_deps.values():
                if isinstance(grp, list):
                    all_raw.extend(grp)
            for grp in dep_groups.values():
                if isinstance(grp, list):
                    all_raw.extend(x for x in grp if isinstance(x, str))
            if isinstance(poetry_deps, dict):
                all_raw.extend(poetry_deps.keys())
            for item in all_raw:
                _add_pkg(str(item))
        except (ImportError, ValueError):
            for m in re.finditer(r'"([a-zA-Z0-9_.\-]+)(?:[<>=!~\[;][^"]*)?"', text):
                _add_pkg(m.group(1))

    pkg_json = root / "package.json"
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                if isinstance(data.get(sec), dict):
                    for k in data[sec]:
                        deps.add(k.lower())
        except (json.JSONDecodeError, OSError):
            pass

    return deps


def collect_local_modules(root: Path) -> set[str]:
    """Discover local top-level Python modules and packages in the repo."""
    local: set[str] = set()
    search_roots = [root]
    if (root / "src").is_dir():
        search_roots.append(root / "src")
    if (root / "tests").is_dir():
        search_roots.append(root / "tests")

    for base in search_roots:
        if not base.is_dir():
            continue
        for entry in base.iterdir():
            if entry.name.startswith("."):
                continue
            if entry.is_file() and entry.suffix == ".py":
                local.add(entry.stem.lower())
            elif entry.is_dir() and ((entry / "__init__.py").is_file() or any(entry.glob("*.py"))):
                local.add(entry.name.lower())
    return local


def _has_nearest_package_json(file_path: Path) -> bool:
    for parent in [file_path.parent, *file_path.parent.parents]:
        if (parent / "package.json").is_file():
            return True
    return False


def _is_type_checking_guard(node: ast.If) -> bool:
    test = node.test
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    return False


def _collect_guarded_import_lines(tree: ast.AST) -> set[int]:
    """Return line numbers of imports inside `try ... except ImportError` or `if TYPE_CHECKING`."""
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            handles_import_err = any(
                isinstance(h.type, ast.Name) and h.type.id in {"ImportError", "ModuleNotFoundError"}
                for h in node.handlers
            )
            if handles_import_err:
                for sub in ast.walk(node):
                    if isinstance(sub, (ast.Import, ast.ImportFrom)):
                        guarded.add(sub.lineno)
        elif isinstance(node, ast.If) and _is_type_checking_guard(node):
            for sub in ast.walk(node):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    guarded.add(sub.lineno)
    return guarded


def detect_phantom_imports(
    file_path: Path,
    rel_path: str,
    content: str,
    declared_deps: set[str],
    local_modules: set[str],
    tree: ast.AST | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    suffix = file_path.suffix.lower()

    if suffix == ".py":
        if tree is None:
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError:
                return findings

        guarded_lines = _collect_guarded_import_lines(tree)
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if node.lineno in guarded_lines:
                    continue
                for alias in node.names:
                    top = alias.name.split(".", 1)[0].lower()
                    if _is_known_python_module(top, declared_deps, local_modules):
                        continue
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
            elif isinstance(node, ast.ImportFrom):
                if node.lineno in guarded_lines or node.level > 0 or not node.module:
                    continue
                top = node.module.split(".", 1)[0].lower()
                if _is_known_python_module(top, declared_deps, local_modules):
                    continue
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

    elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        if not _has_nearest_package_json(file_path):
            return findings
        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            for m in _JS_IMPORT_RE.finditer(line):
                spec = m.group(1)
                if spec.startswith(".") or spec.startswith("/") or spec.startswith("@/") or spec.startswith("~/"):
                    continue
                if spec.startswith("node:"):
                    continue
                pkg = spec.split("/")[0] if not spec.startswith("@") else "/".join(spec.split("/")[:2])
                pkg_lower = pkg.lower()
                if pkg_lower in NODE_BUILTINS or pkg_lower in declared_deps:
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


def _is_known_python_module(top: str, declared_deps: set[str], local_modules: set[str]) -> bool:
    norm = top.lower().replace("-", "_")
    if top in STDLIB_MODULES or norm in STDLIB_MODULES:
        return True
    if norm in local_modules or top in local_modules:
        return True
    if norm in declared_deps or top in declared_deps:
        return True
    return False
