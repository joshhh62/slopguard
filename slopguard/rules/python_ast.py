"""Precise checks for Python, using the standard-library AST (no third-party parser needed).

Other languages get the text-based equivalents in ``gaps.py`` / ``loose_ends.py``; these rules
simply raise precision where a free, exact parser exists.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..context import FileContext, RepoContext
from ..models import Category, Finding, Severity
from .base import Rule, RuleMeta, register

_PY = frozenset({"python"})
_TERMINAL = (ast.Return, ast.Raise, ast.Continue, ast.Break)


def _is_trivial(stmt: ast.stmt) -> bool:
    """`pass`, `...` or a bare string (docstring)."""
    return isinstance(stmt, ast.Pass) or (
        isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
        and (stmt.value.value is Ellipsis or isinstance(stmt.value.value, str))
    )


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> set[str]:
    names = set()
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        names.add(ast.unparse(target).rsplit(".", 1)[-1])
    return names


class _PythonRule(Rule):
    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        tree = ctx.python_ast
        if tree is not None:
            yield from self.check_tree(ctx, tree)

    def check_tree(self, ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
        """Subclasses yield findings for one parsed module."""
        return iter(())


@register
class SwallowedExceptionPythonRule(_PythonRule):
    meta = RuleMeta(
        id="GAP011", title="Exception silently swallowed", category=Category.GAP, severity=Severity.HIGH,
        description="An except block discards the error (only `pass`/`...`/`continue`), hiding real failures.",
        fix="Log the exception with context, re-raise, or catch only the specific error you expect.",
        languages=_PY,
    )

    def check_tree(self, ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
        nodes = ctx.python_nodes
        for node in nodes:
            if isinstance(node, ast.ExceptHandler) and all(
                _is_trivial(s) or isinstance(s, ast.Continue) for s in node.body
            ):
                caught = ast.unparse(node.type) if node.type else "everything"
                specific = node.type is not None and not re.search(r"\b(?:Base)?Exception\b", caught)
                if specific and any(isinstance(s, ast.Continue) for s in node.body):
                    continue  # skipping one item on a specific, expected error is deliberate
                yield self.finding(
                    ctx, node.lineno, f"Catches {caught} and silently ignores it.",
                    severity=Severity.LOW if specific else Severity.HIGH,
                    confidence=0.6 if specific else 0.9, source="ast",
                )


@register
class BareExceptRule(_PythonRule):
    meta = RuleMeta(
        id="GAP002", title="Bare except", category=Category.GAP, severity=Severity.MEDIUM,
        description="`except:` also catches KeyboardInterrupt and SystemExit and masks programming errors.",
        fix="Catch a specific exception class (or at minimum `except Exception:`) and handle it.",
        languages=_PY,
    )

    def check_tree(self, ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
        nodes = ctx.python_nodes
        for node in nodes:
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                yield self.finding(ctx, node.lineno, "Bare `except:` catches every exception.", source="ast",
                                   confidence=0.95)


@register
class MutableDefaultRule(_PythonRule):
    meta = RuleMeta(
        id="GAP003", title="Mutable default argument", category=Category.GAP, severity=Severity.MEDIUM,
        description="Default values are created once; a list/dict/set default is shared and mutated across calls.",
        fix="Default to None and create the object inside the function.",
        languages=_PY,
    )

    def check_tree(self, ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
        nodes = ctx.python_nodes
        for node in nodes:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for default in [*node.args.defaults, *[d for d in node.args.kw_defaults if d is not None]]:
                mutable = isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                    isinstance(default, ast.Call) and isinstance(default.func, ast.Name)
                    and default.func.id in {"list", "dict", "set", "defaultdict"}
                )
                if mutable:
                    yield self.finding(ctx, default.lineno,
                                       f"`{node.name}()` has a mutable default `{ast.unparse(default)}`.",
                                       source="ast", confidence=0.95)


@register
class UnusedImportRule(_PythonRule):
    meta = RuleMeta(
        id="LOOSE004", title="Unused import", category=Category.LOOSE_END, severity=Severity.LOW,
        description="An imported name is never used - dead weight left over from refactors or generation.",
        fix="Remove the import.",
        languages=_PY,
    )

    def check_tree(self, ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
        if ctx.rel.endswith("__init__.py"):
            return  # re-export hub
        used: set[str] = set()
        strings: list[str] = []
        nodes = ctx.python_nodes
        for node in nodes:
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                root = node
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(root, ast.Name):
                    used.add(root.id)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                strings.append(node.value)  # string annotations, __all__
        string_blob = " ".join(strings)
        for node in tree.body:  # module-level imports only; local imports are usually deliberate
            if isinstance(node, ast.Import):
                names = [(a.asname or a.name.split(".")[0], a) for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                names = [(a.asname or a.name, a) for a in node.names if a.name != "*"]
            else:
                continue
            for bound, alias in names:
                if alias.asname and alias.asname == alias.name:
                    continue  # explicit re-export idiom: `import x as x`
                if "noqa" in ctx.line(node.lineno):
                    continue  # explicitly kept for its side effects
                if bound not in used and not re.search(rf"\b{re.escape(bound)}\b", string_blob):
                    yield self.finding(ctx, node.lineno, f"`{bound}` is imported but never used.",
                                       source="ast", confidence=0.9)


@register
class UnreachableCodeRule(_PythonRule):
    meta = RuleMeta(
        id="LOOSE006", title="Unreachable code", category=Category.LOOSE_END, severity=Severity.MEDIUM,
        description="Statements after return/raise/break/continue can never run.",
        fix="Delete the dead statements or fix the control flow that was meant to reach them.",
        languages=_PY,
    )

    def check_tree(self, ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
        nodes = ctx.python_nodes
        for node in nodes:
            for field in ("body", "orelse", "finalbody"):
                block = getattr(node, field, None)
                if not isinstance(block, list):
                    continue
                for i, stmt in enumerate(block[:-1]):
                    if isinstance(stmt, _TERMINAL):
                        nxt = block[i + 1]
                        yield self.finding(ctx, nxt.lineno,
                                           f"Unreachable after `{type(stmt).__name__.lower()}` on line {stmt.lineno}.",
                                           source="ast", confidence=0.95)
                        break


@register
class EmptyFunctionRule(_PythonRule):
    meta = RuleMeta(
        id="LOOSE007", title="Empty function body", category=Category.LOOSE_END, severity=Severity.MEDIUM,
        description="A function's body is only `pass`/`...` - it silently does nothing when called.",
        fix="Implement it, raise NotImplementedError with a reason, or delete it.",
        languages=_PY,
        include_tests=False,
    )
    _EXEMPT_DECORATORS = {"abstractmethod", "overload", "abstractproperty", "property", "setter", "fixture"}

    def check_tree(self, ctx: FileContext, tree: ast.Module) -> Iterator[Finding]:
        exempt_classes: set[int] = set()
        nodes = ctx.python_nodes
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                bases = {ast.unparse(b).rsplit(".", 1)[-1] for b in node.bases}
                if bases & {"ABC", "Protocol", "Exception", "BaseException", "TypedDict", "NamedTuple"} or \
                        node.name.endswith(("Error", "Exception", "Protocol", "Base", "Mixin", "Interface")):
                    exempt_classes.update(id(n) for n in node.body)
        for node in nodes:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or id(node) in exempt_classes:
                continue
            if _decorator_names(node) & self._EXEMPT_DECORATORS or node.name.startswith("__"):
                continue
            if any(isinstance(s, ast.Pass) for s in node.body) and all(_is_trivial(s) for s in node.body) and not (
                len(node.body) == 1 and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str)
            ):
                yield self.finding(ctx, node.lineno, f"`{node.name}()` has an empty body.", source="ast",
                                   confidence=0.8)


_JS_FUNCTION = re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(")


@register
class UnreferencedFunctionRule(Rule):
    meta = RuleMeta(
        id="LOOSE005", title="Function is never referenced", category=Category.LOOSE_END, severity=Severity.LOW,
        description="A top-level function is defined but its name appears nowhere else in the repository.",
        fix="Delete it if it is dead, or wire it up / export it if it was meant to be used.",
        languages=frozenset({"python", "javascript", "typescript"}),
        include_tests=False,
    )

    def check_file(self, ctx: FileContext) -> Iterator[Finding]:
        return ()  # needs whole-repo knowledge; see check_repo

    def check_repo(self, repo: RepoContext) -> Iterator[Finding]:
        counts = repo.identifier_counts
        for ctx in repo.files:
            if not self.applies_to(ctx) or ctx.rel.rsplit("/", 1)[-1] in {"__init__.py", "__main__.py", "conftest.py"}:
                continue
            for name, lineno in self._definitions(ctx):
                if name.startswith(("_", "test", "main", "handler", "setup", "teardown")):
                    continue
                if counts.get(name, 0) <= 1:
                    yield self.finding(ctx, lineno, f"`{name}` is defined but never referenced anywhere in the repo.",
                                       source="ast" if ctx.language.name == "python" else "heuristic",
                                       confidence=0.6)

    @staticmethod
    def _definitions(ctx: FileContext) -> Iterator[tuple[str, int]]:
        if ctx.language.name == "python":
            tree = ctx.python_ast
            if tree is None:
                return
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.decorator_list:
                    yield node.name, node.lineno
        else:
            for lineno, line in enumerate(ctx.lines, 1):
                match = _JS_FUNCTION.match(line)
                if match:
                    yield match.group(1), lineno
