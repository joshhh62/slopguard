"""Language registry.

SlopGuard is architecture agnostic: instead of a parser per language, every detector works
on a small, declarative description of how a language spells comments. Languages that do
have a cheap, reliable parser in the standard library (Python) get extra AST-based rules on
top, but nothing depends on them.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Language:
    name: str
    line_comments: tuple[str, ...] = ()
    block_comment: tuple[str, str] | None = None
    is_code: bool = True  # False for config/markup files: only secret & hygiene rules apply


_C_STYLE = ("//",)
_C_BLOCK = ("/*", "*/")

_LANGUAGES = {
    "python": Language("python", ("#",)),
    "javascript": Language("javascript", _C_STYLE, _C_BLOCK),
    "typescript": Language("typescript", _C_STYLE, _C_BLOCK),
    "java": Language("java", _C_STYLE, _C_BLOCK),
    "kotlin": Language("kotlin", _C_STYLE, _C_BLOCK),
    "scala": Language("scala", _C_STYLE, _C_BLOCK),
    "go": Language("go", _C_STYLE, _C_BLOCK),
    "rust": Language("rust", _C_STYLE, _C_BLOCK),
    "c": Language("c", _C_STYLE, _C_BLOCK),
    "cpp": Language("cpp", _C_STYLE, _C_BLOCK),
    "csharp": Language("csharp", _C_STYLE, _C_BLOCK),
    "swift": Language("swift", _C_STYLE, _C_BLOCK),
    "dart": Language("dart", _C_STYLE, _C_BLOCK),
    "php": Language("php", ("//", "#"), _C_BLOCK),
    "ruby": Language("ruby", ("#",)),
    "shell": Language("shell", ("#",)),
    "powershell": Language("powershell", ("#",), ("<#", "#>")),
    "lua": Language("lua", ("--",)),
    "sql": Language("sql", ("--",), _C_BLOCK),
    "r": Language("r", ("#",)),
    "elixir": Language("elixir", ("#",)),
    "vue": Language("vue", _C_STYLE, _C_BLOCK),
    "svelte": Language("svelte", _C_STYLE, _C_BLOCK),
    "html": Language("html", (), ("<!--", "-->"), is_code=False),
    "yaml": Language("yaml", ("#",), is_code=False),
    "toml": Language("toml", ("#",), is_code=False),
    "ini": Language("ini", (";", "#"), is_code=False),
    "json": Language("json", (), is_code=False),
    "xml": Language("xml", (), ("<!--", "-->"), is_code=False),
    "dotenv": Language("dotenv", ("#",), is_code=False),
    "dockerfile": Language("dockerfile", ("#",), is_code=False),
    "terraform": Language("terraform", ("#", "//"), _C_BLOCK, is_code=False),
    "properties": Language("properties", ("#", "!"), is_code=False),
}

_EXTENSIONS = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".go": "go", ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".cs": "csharp", ".swift": "swift", ".dart": "dart", ".php": "php", ".rb": "ruby",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "powershell",
    ".lua": "lua", ".sql": "sql", ".r": "r", ".ex": "elixir", ".exs": "elixir",
    ".vue": "vue", ".svelte": "svelte",
    ".html": "html", ".htm": "html",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".ini": "ini", ".cfg": "ini",
    ".json": "json", ".xml": "xml", ".tf": "terraform", ".properties": "properties",
}

_FILENAMES = {
    "dockerfile": "dockerfile",
    "makefile": "shell",
    ".env": "dotenv",
}


def detect_language(filename: str) -> Language | None:
    """Return the language for a file name, or None if SlopGuard should not read it."""
    lower = filename.lower()
    if lower in _FILENAMES:
        return _LANGUAGES[_FILENAMES[lower]]
    if lower.startswith(".env"):  # .env.local, .env.production, ...
        return _LANGUAGES["dotenv"]
    if lower.startswith("dockerfile"):
        return _LANGUAGES["dockerfile"]
    dot = lower.rfind(".")
    if dot == -1:
        return None
    name = _EXTENSIONS.get(lower[dot:])
    return _LANGUAGES[name] if name else None
