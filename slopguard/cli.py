"""Command-line interface: ``slopguard scan``, ``slopguard rules``, ``slopguard explain``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .engine import ScanOptions, scan, write_baseline
from .models import Category, Severity, Verdict
from .reporters import FILE_FORMATS
from .reporters.console import render
from .rules import all_rules
from .scoring import score_findings

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slopguard",
        description="Architecture-agnostic agent that finds security holes, AI slop, coding gaps and loose ends.",
    )
    parser.add_argument("--version", action="version", version=f"slopguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path", nargs="?", default=".", help="repository root (default: current directory)")
    s.add_argument("-f", "--format", default="console",
                   help="comma-separated: console,md,json,sarif,html (default: console)")
    s.add_argument("-o", "--output", default=".slopguard", help="directory for file reports (default: .slopguard)")
    s.add_argument("--ai", action="store_true", help="run the Claude triage agent on the findings (needs ANTHROPIC_API_KEY)")
    s.add_argument("--model", default=None, help="Claude model for --ai (default: claude-opus-5-5)")
    s.add_argument("--effort", default="medium", choices=["low", "medium", "high", "xhigh", "max"],
                   help="reasoning effort for --ai (default: medium)")
    s.add_argument("--ai-max-files", type=int, default=20, help="max files the agent triages (default: 20)")
    s.add_argument("--min-severity", default="info", help="hide findings below this severity")
    s.add_argument("--fail-on", default=None,
                   help="exit 1 if any open finding is at or above this severity (e.g. high) - for CI")
    s.add_argument("--category", default=None, help="only these categories: security,slop,gap,loose-end")
    s.add_argument("--rules", default=None, help="only these rule ids, comma-separated")
    s.add_argument("--exclude", action="append", default=[], help="extra glob to exclude (repeatable)")
    s.add_argument("--diff", metavar="GIT_REF", default=None, help="only report lines changed since GIT_REF")
    s.add_argument("--baseline", type=Path, default=None, help="hide findings recorded in this baseline file")
    s.add_argument("--write-baseline", type=Path, default=None, help="record current findings as accepted debt")
    s.add_argument("--config", type=Path, default=None, help="config file (default: .slopguard.toml)")
    s.add_argument("--show-dismissed", action="store_true", help="also print findings the AI marked false positive")
    s.add_argument("--limit", type=int, default=60, help="max findings printed to the console (default: 60)")

    w = sub.add_parser("serve", help="open the interactive web dashboard")
    w.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    w.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1, local only)")
    w.add_argument("--no-browser", action="store_true", help="do not open a browser tab")

    sub.add_parser("rules", help="list every built-in rule")
    e = sub.add_parser("explain", help="explain one rule")
    e.add_argument("rule_id")
    return parser


def _output_exclude(root: Path, output: Path) -> list[str]:
    """Never scan our own previous reports if the output directory lives inside the repo."""
    try:
        rel = output.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return []
    return [f"{rel}/"] if rel not in {"", "."} else []


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    formats = _csv(args.format)
    unknown = [f for f in formats if f != "console" and f not in FILE_FORMATS]
    if unknown:
        print(f"error: unknown format(s): {', '.join(unknown)}", file=sys.stderr)
        return EXIT_ERROR
    categories = set(_csv(args.category)) if args.category else None
    if categories and not categories <= {c.value for c in Category}:
        print(f"error: categories must be from: {', '.join(c.value for c in Category)}", file=sys.stderr)
        return EXIT_ERROR

    options = ScanOptions(
        min_severity=Severity.parse(args.min_severity),
        categories=categories,
        only_rules={r.upper() for r in _csv(args.rules)} if args.rules else None,
        baseline=args.baseline,
        diff_ref=args.diff,
        config_path=args.config,
        extra_excludes=list(args.exclude) + _output_exclude(root, Path(args.output)),
    )
    result, repo = scan(root, options)

    if args.ai:
        from .agent import DEFAULT_MODEL, AgentSettings, TriageAgent

        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            print("note: no ANTHROPIC_API_KEY set - trying the SDK's default credentials", file=sys.stderr)
        settings = AgentSettings(model=args.model or DEFAULT_MODEL, effort=args.effort, max_files=args.ai_max_files)
        print(f"AI triage: {settings.model} reviewing up to {settings.max_files} files...", file=sys.stderr)
        try:
            outcome = TriageAgent(repo, settings).run(result.findings)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        result.findings = sorted(outcome.findings, key=lambda f: (-f.severity.rank, f.category.value, f.path, f.line))
        result.ai_summary, result.ai_usage = outcome.summary, outcome.usage
        result.score, result.grade = score_findings(result.findings, result.stats.lines_scanned)

    if args.write_baseline:
        write_baseline(result.findings, args.write_baseline)
        print(f"baseline with {len(result.findings)} findings written to {args.write_baseline}", file=sys.stderr)

    if "console" in formats:
        render(result, show_dismissed=args.show_dismissed, limit=args.limit)
    file_formats = [f for f in formats if f != "console"]
    if file_formats:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        for fmt in file_formats:
            filename, renderer = FILE_FORMATS[fmt]
            target = out_dir / filename
            target.write_text(renderer(result), encoding="utf-8")
            print(f"wrote {target}", file=sys.stderr)

    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        blocking = [f for f in result.findings
                    if f.severity.rank >= threshold.rank and f.verdict is not Verdict.FALSE_POSITIVE]
        if blocking:
            print(f"failing: {len(blocking)} open finding(s) at or above '{threshold.value}'", file=sys.stderr)
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules() -> int:
    for cat in Category:
        print(f"\n{cat.label}")
        for rule in all_rules():
            if rule.meta.category is cat:
                print(f"  {rule.meta.id:<9} {rule.meta.severity.value:<9} {rule.meta.title}")
    print("\nAI-* ids are issues discovered by the triage agent (--ai).")
    return EXIT_OK


def cmd_explain(rule_id: str) -> int:
    rule = next((r for r in all_rules() if r.meta.id == rule_id.upper()), None)
    if rule is None:
        print(f"unknown rule {rule_id!r}; run `slopguard rules`", file=sys.stderr)
        return EXIT_ERROR
    m = rule.meta
    langs = ", ".join(sorted(m.languages)) if m.languages else "all languages"
    print(f"{m.id}  {m.title}\n  category: {m.category.label}\n  default severity: {m.severity.value}\n"
          f"  applies to: {langs}{' + config files' if m.include_config_files else ''}\n\n"
          f"  Why: {m.description}\n  Fix: {m.fix}\n\n"
          f"  Suppress one occurrence with a comment containing: slopguard: ignore[{m.id}]")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "rules":
            return cmd_rules()
        if args.command == "serve":
            from .web.server import serve

            serve(args.host, args.port, open_browser=not args.no_browser)
            return EXIT_OK
        return cmd_explain(args.rule_id)
    except (ValueError, NotADirectoryError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
