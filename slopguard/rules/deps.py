"""Undeclared / hallucinated dependencies.

LLMs regularly invent plausible package names. Attackers register those names on PyPI/npm
("slopsquatting"), so an import that no manifest declares is both a build gap and a supply
chain risk. We cross-check every import against the manifests and the repo's own modules.
"""

from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from collections.abc import Iterator

from ..context import FileContext, RepoContext
from ..models import Category, Finding, Severity
from .base import Rule, RuleMeta, register

# import name -> distribution name, for the common cases where they differ.
_PY_ALIASES = {
    "pil": "pillow", "yaml": "pyyaml", "cv2": "opencv-python", "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv", "jwt": "pyjwt", "attr": "attrs", "dateutil": "python-dateutil",
    "crypto": "pycryptodome", "magic": "python-magic", "serial": "pyserial", "usb": "pyusb",
    "openssl": "pyopenssl", "mysqldb": "mysqlclient", "psycopg2": "psycopg2-binary", "git": "gitpython",
    "docx": "python-docx", "pptx": "python-pptx", "fitz": "pymupdf", "telegram": "python-telegram-bot",
    "jose": "python-jose", "multipart": "python-multipart", "google": "google-*", "googleapiclient":
    "google-api-python-client", "skimage": "scikit-image", "slugify": "python-slugify", "zmq": "pyzmq",
    "win32api": "pywin32", "win32con": "pywin32", "dns": "dnspython", "ldap": "python-ldap",
    "flask_sqlalchemy": "flask-sqlalchemy", "socketio": "python-socketio", "engineio": "python-engineio",
    "pkg_resources": "setuptools", "setuptools": "setuptools", "_pytest": "pytest", "typing_extensions":
    "typing-extensions", "nacl": "pynacl", "markdown": "markdown", "lxml": "lxml",
}
# Tools that are almost always present in a dev environment without being declared at runtime.
_PY_IMPLICIT = {"pytest", "setuptools", "pip", "wheel", "pkg_resources", "_pytest", "conftest", "typing_extensions"}

_NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
    "worker_threads", "zlib", "test",
}
_JS_IMPORT = re.compile(
    r"""(?:\bfrom\s+|\bimport\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)["']([^"'\s]+)["']"""
)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _req_name(spec: str) -> str | None:
    spec = spec.split(";")[0].split("#")[0].strip()
    match = re.match(r"([A-Za-z0-9][A-Za-z0-9._\-]*)", spec)
    return _norm(match.group(1)) if match and not spec.startswith("-") else None


def python_declared(repo: RepoContext) -> set[str] | None:
    """Every distribution declared by any Python manifest, or None if there is no manifest."""
    declared: set[str] = set()
    found = False
    for rel in repo.inventory:
        name = rel.rsplit("/", 1)[-1].lower()
        if re.fullmatch(r"requirements[\w.\-]*\.(?:txt|in)", name):
            text = repo.read_text(rel) or ""
            declared.update(n for n in map(_req_name, text.splitlines()) if n)
        elif name in {"pyproject.toml", "pipfile"}:
            try:
                data = tomllib.loads(repo.read_text(rel) or "")
            except (tomllib.TOMLDecodeError, ValueError):
                data = {}
            project = data.get("project", {})
            specs = list(project.get("dependencies", []))
            for group in project.get("optional-dependencies", {}).values():
                specs.extend(group)
            for group in data.get("dependency-groups", {}).values():
                specs.extend(s for s in group if isinstance(s, str))
            poetry = data.get("tool", {}).get("poetry", {})
            for table in (poetry.get("dependencies", {}), poetry.get("dev-dependencies", {}),
                          data.get("packages", {}), data.get("dev-packages", {})):
                specs.extend(table.keys())
            for group in poetry.get("group", {}).values():
                specs.extend(group.get("dependencies", {}).keys())
            if project.get("name"):
                specs.append(project["name"])
            declared.update(n for n in map(_req_name, specs) if n)
        elif name in {"setup.py", "setup.cfg"}:
            text = repo.read_text(rel) or ""
            declared.update(_norm(m) for m in re.findall(r"[\"']([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:[<>=!~;\[][^\"']*)?[\"']", text))
            declared.update(n for n in map(_req_name, text.splitlines()) if n)
        else:
            continue
        found = True
    return declared if found else None


def _local_python_modules(repo: RepoContext) -> set[str]:
    local = set()
    for f in repo.files:
        if f.language.name == "python":
            parts = f.rel[:-3].split("/") if f.rel.endswith(".py") else f.rel.split("/")
            local.update(p.lower() for p in parts)
    for rel in repo.inventory:  # namespace packages, compiled extensions, etc.
        local.update(p.lower() for p in rel.split("/")[:-1])
    return local


def _python_imports(nodes: list[ast.AST]) -> Iterator[tuple[str, int]]:
    optional_lines: set[int] = set()
    for node in nodes:
        if isinstance(node, ast.Try) and any(
            h.type is None or re.search(r"ImportError|ModuleNotFoundError|Exception", ast.unparse(h.type))
            for h in node.handlers
        ):
            for child in node.body:
                optional_lines.update(range(child.lineno, (child.end_lineno or child.lineno) + 1))
        if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.unparse(node.test):
            for child in node.body:
                optional_lines.update(range(child.lineno, (child.end_lineno or child.lineno) + 1))
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if node.lineno not in optional_lines:
                    yield alias.name.split(".")[0], node.lineno
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.lineno not in optional_lines:
                yield node.module.split(".")[0], node.lineno


def _js_declared(repo: RepoContext) -> set[str] | None:
    declared: set[str] = set()
    found = False
    for rel in repo.inventory:
        if rel.rsplit("/", 1)[-1] != "package.json":
            continue
        try:
            data = json.loads(repo.read_text(rel) or "{}")
        except json.JSONDecodeError:
            continue
        found = True
        if isinstance(data.get("name"), str):
            declared.add(data["name"])
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            declared.update((data.get(key) or {}).keys())
        declared.update((data.get("imports") or {}).keys())
    return declared if found else None


def _js_package(spec: str) -> str | None:
    if spec.startswith((".", "/", "~", "#", "@/", "node:", "virtual:", "data:", "http:", "https:", "$")):
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


@register
class UndeclaredDependencyRule(Rule):
    meta = RuleMeta(
        id="SLOP004", title="Undeclared (possibly hallucinated) dependency", category=Category.SLOP,
        severity=Severity.HIGH,
        description="Code imports a package that no manifest declares. AI tools often invent package names that "
                    "attackers then register (slopsquatting).",
        fix="Verify the package really exists and is the one you intend, then declare and pin it - or remove the import.",
    )

    def check_repo(self, repo: RepoContext) -> Iterator[Finding]:
        yield from self._python(repo)
        yield from self._javascript(repo)

    def _python(self, repo: RepoContext) -> Iterator[Finding]:
        declared = python_declared(repo)
        if declared is None:
            return
        stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
        local = _local_python_modules(repo)
        reported: set[str] = set()
        for ctx in repo.files:
            if ctx.python_ast is None:
                continue
            for module, lineno in _python_imports(ctx.python_nodes):
                key = module.lower()
                if module in stdlib or key in local or key in _PY_IMPLICIT or key in reported:
                    continue
                dist = _norm(_PY_ALIASES.get(key, module))
                if dist in declared or _norm(module) in declared or (
                    dist.endswith("*") and any(d.startswith(dist[:-1]) for d in declared)
                ):
                    continue
                reported.add(key)
                yield self._report(ctx, lineno, module, "Python manifest")

    def _javascript(self, repo: RepoContext) -> Iterator[Finding]:
        declared = _js_declared(repo)
        if declared is None:
            return
        reported: set[str] = set()
        for ctx in repo.files:
            if ctx.language.name not in {"javascript", "typescript", "vue", "svelte"}:
                continue
            for lineno, line in enumerate(ctx.lines, 1):
                if ctx.comment_only(lineno):
                    continue
                for spec in _JS_IMPORT.findall(line):
                    pkg = _js_package(spec)
                    if not pkg or pkg in _NODE_BUILTINS or pkg in declared or pkg in reported:
                        continue
                    if pkg.startswith("@types/") or f"@types/{pkg}" in declared:
                        continue
                    reported.add(pkg)
                    yield self._report(ctx, lineno, pkg, "package.json")

    def _report(self, ctx: FileContext, lineno: int, name: str, manifest: str) -> Finding:
        severity = Severity.MEDIUM if ctx.is_test else Severity.HIGH
        return self.finding(
            ctx, lineno, f"`{name}` is imported but not declared in any {manifest}.",
            severity=severity, confidence=0.75,
        )
