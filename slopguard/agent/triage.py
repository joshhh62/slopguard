"""The AI triage agent.

Pipeline position: the deterministic scanner produces *candidates*; this agent verifies each
one against the real code using read-only tools, corrects severities, writes tailored fixes,
reports issues the rules missed, and finally writes an executive summary.

Design notes
- Manual tool-use loop on the official Anthropic SDK (no beta features needed).
- Work is split into per-file batches that run concurrently, each with its own turn budget,
  so one large repo cannot run up an unbounded bill.
- Any API failure degrades gracefully: affected candidates keep their static result.
- The client is injectable, which is how the test-suite exercises the loop without network.
"""

from __future__ import annotations

import json
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from ..context import RepoContext
from ..models import Category, Finding, Severity, Verdict
from ..scoring import WEIGHTS
from .prompts import SUMMARY_PROMPT, SYSTEM_PROMPT
from .tools import TOOL_SCHEMAS, RepoTools, ToolError, clip

DEFAULT_MODEL = "claude-opus-5-5"
CONTEXT_LINES = 4

# USD per million tokens: (input, output, cache read). Used only for the cost estimate shown to users.
PRICING = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.10),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
}


@dataclass
class AgentSettings:
    model: str = DEFAULT_MODEL
    effort: str = "medium"
    max_files: int = 20
    max_findings_per_batch: int = 25
    max_turns: int = 12
    concurrency: int = 4
    max_tokens: int = 16000


@dataclass
class Usage:
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    tool_calls: int = 0
    errors: list[str] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, response: Any) -> None:
        usage = getattr(response, "usage", None)
        with self._lock:
            self.requests += 1
            if usage is not None:
                self.input_tokens += getattr(usage, "input_tokens", 0) or 0
                self.output_tokens += getattr(usage, "output_tokens", 0) or 0
                self.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0

    def to_dict(self, model: str) -> dict[str, Any]:
        price = PRICING.get(model)
        cost = None
        if price:
            cost = round((self.input_tokens * price[0] + self.output_tokens * price[1]
                          + self.cache_read_tokens * price[2]) / 1_000_000, 4)
        return {
            "model": model, "requests": self.requests, "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens, "cache_read_tokens": self.cache_read_tokens,
            "tool_calls": self.tool_calls, "estimated_cost_usd": cost, "errors": self.errors,
        }


@dataclass
class TriageOutcome:
    findings: list[Finding]
    summary: str
    usage: dict[str, Any]


class TriageAgent:
    def __init__(self, repo: RepoContext, settings: AgentSettings | None = None, client: Any = None):
        self.repo = repo
        self.settings = settings or AgentSettings()
        self.tools = RepoTools(repo)
        self.usage = Usage()
        self._client = client
        self._new_findings: list[Finding] = []
        self._summaries: list[str] = []
        self._lock = threading.Lock()

    @property
    def client(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise RuntimeError("AI triage needs the Anthropic SDK: pip install 'slopguard[ai]'") from exc
            self._client = anthropic.Anthropic()
        return self._client

    # -- public API -------------------------------------------------------------------
    def run(self, findings: list[Finding]) -> TriageOutcome:
        batches = self._plan_batches(findings)
        if batches:
            workers = max(1, min(self.settings.concurrency, len(batches)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(self._run_batch, batches))
        all_findings = findings + self._new_findings
        summary = self._executive_summary(all_findings) if (batches or all_findings) else ""
        return TriageOutcome(all_findings, summary, self.usage.to_dict(self.settings.model))

    # -- planning ---------------------------------------------------------------------
    def _plan_batches(self, findings: list[Finding]) -> list[list[tuple[str, Finding]]]:
        """Group file-level candidates by file, riskiest files first, within the file budget."""
        by_file: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            if f.path and f.line and f.severity is not Severity.INFO:
                by_file[f.path].append(f)
        ranked = sorted(by_file.items(), key=lambda kv: -sum(WEIGHTS[f.severity] for f in kv[1]))
        ranked = ranked[: self.settings.max_files]

        batches: list[list[tuple[str, Finding]]] = []
        current: list[tuple[str, Finding]] = []
        counter = 0
        for _, items in ranked:
            items = sorted(items, key=lambda f: (-f.severity.rank, f.line))[: self.settings.max_findings_per_batch]
            if current and len(current) + len(items) > self.settings.max_findings_per_batch:
                batches.append(current)
                current = []
            for f in items:
                counter += 1
                current.append((f"F{counter}", f))
        if current:
            batches.append(current)
        return batches

    def _render_candidates(self, batch: list[tuple[str, Finding]]) -> str:
        files = {f.rel: f for f in self.repo.files}
        blocks = []
        for fid, f in batch:
            ctx = files.get(f.path)
            excerpt = ""
            if ctx:
                lo, hi = max(1, f.line - CONTEXT_LINES), min(len(ctx.lines), f.line + CONTEXT_LINES)
                excerpt = "\n".join(
                    f"{'>' if n == f.line else ' '}{n:>5} | {ctx.lines[n - 1]}" for n in range(lo, hi + 1)
                )
            if f.category is Category.SECURITY and f.rule_id.startswith(("SEC001", "SEC002")):
                excerpt = f"(secret value redacted) {f.snippet}"
            blocks.append(
                f"[{fid}] {f.rule_id} {f.title} | severity={f.severity.value} | {f.location}\n"
                f"scanner says: {f.message}\n{excerpt}"
            )
        return "\n\n".join(blocks)

    def _overview(self) -> str:
        langs = ", ".join(f"{k} ({v})" for k, v in list(_language_counts(self.repo).items())[:8])
        manifests = [p for p in self.repo.inventory if p.rsplit("/", 1)[-1] in {
            "package.json", "pyproject.toml", "requirements.txt", "go.mod", "pom.xml", "Cargo.toml",
            "build.gradle", "Gemfile", "composer.json"}]
        return (f"Repository: {self.repo.root.name}\nFiles scanned: {len(self.repo.files)}\n"
                f"Languages: {langs}\nManifests: {', '.join(manifests[:10]) or 'none'}")

    # -- the agent loop ---------------------------------------------------------------
    def _run_batch(self, batch: list[tuple[str, Finding]]) -> None:
        pending = {fid: f for fid, f in batch}
        messages: list[dict[str, Any]] = [{
            "role": "user",
            "content": (
                f"{self._overview()}\n\n<candidates>\n{self._render_candidates(batch)}\n</candidates>\n\n"
                f"Triage all {len(batch)} candidates, report anything important they missed in these files, "
                "then call finish."
            ),
        }]
        nudged = False
        for _ in range(self.settings.max_turns):
            try:
                response = self.client.messages.create(
                    model=self.settings.model,
                    max_tokens=self.settings.max_tokens,
                    system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                    tools=TOOL_SCHEMAS,
                    output_config={"effort": self.settings.effort},
                    messages=messages,
                )
            except Exception as exc:  # network/API errors must not lose the static results
                self._record_error(f"{type(exc).__name__}: {exc}")
                return
            self.usage.add(response)

            if response.stop_reason == "refusal":
                self._record_error("model declined this batch (stop_reason=refusal); static results kept")
                return
            messages.append({"role": "assistant", "content": response.content})
            tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]

            if not tool_uses:
                if response.stop_reason == "max_tokens" or nudged or not pending:
                    return
                nudged = True  # one reminder if the model stopped before judging everything
                messages.append({"role": "user", "content":
                                 f"These candidates still need record_verdict: {', '.join(sorted(pending))}."})
                continue

            results, finished = [], False
            for block in tool_uses:
                content, is_error = self._dispatch(block.name, block.input, pending)
                finished = finished or block.name == "finish"
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": clip(content), "is_error": is_error})
            messages.append({"role": "user", "content": results})
            if finished:
                return
        self._record_error(f"turn budget exhausted with {len(pending)} candidates untriaged")

    def _dispatch(self, name: str, args: Any, pending: dict[str, Finding]) -> tuple[str, bool]:
        with self._lock:
            self.usage.tool_calls += 1
        if not isinstance(args, dict):
            return "tool input must be a JSON object", True
        try:
            if name == "read_file":
                return self.tools.read_file(str(args["path"]), int(args["start_line"]), int(args["end_line"])), False
            if name == "search_code":
                return self.tools.search_code(str(args["pattern"]), str(args.get("path_glob", ""))), False
            if name == "record_verdict":
                return self._apply_verdict(args, pending), False
            if name == "report_issue":
                return self._add_issue(args), False
            if name == "finish":
                with self._lock:
                    self._summaries.append(str(args.get("summary", "")))
                return "ok", False
            return f"unknown tool {name!r}", True
        except ToolError as exc:
            return str(exc), True
        except (KeyError, TypeError, ValueError) as exc:
            return f"invalid input for {name}: {exc}", True

    def _apply_verdict(self, args: dict[str, Any], pending: dict[str, Finding]) -> str:
        fid = str(args["finding_id"])
        finding = pending.pop(fid, None)
        if finding is None:
            raise ValueError(f"unknown or already-judged finding_id {fid!r}")
        finding.verdict = Verdict(args["verdict"])
        finding.severity = Severity.parse(args["severity"])
        finding.ai_rationale = str(args.get("rationale", "")).strip()
        if args.get("fix"):
            finding.fix = str(args["fix"]).strip()
        if finding.verdict is Verdict.CONFIRMED:
            finding.confidence = max(finding.confidence, 0.9)
        return f"recorded {fid}: {finding.verdict.value}; {len(pending)} remaining"

    def _add_issue(self, args: dict[str, Any]) -> str:
        path = str(args["path"]).replace("\\", "/").lstrip("/")
        if path not in self.repo.all_paths:
            raise ToolError(f"{path!r} is not a scanned file")
        category = Category(args["category"])
        finding = Finding(
            rule_id=f"AI-{category.value.upper().replace('-', '')}",
            title=str(args["title"])[:90],
            category=category,
            severity=Severity.parse(args["severity"]),
            path=path,
            line=max(1, int(args["line"])),
            message=str(args["explanation"]).strip(),
            fix=str(args["fix"]).strip(),
            confidence=0.8,
            source="ai",
            verdict=Verdict.CONFIRMED,
        )
        ctx = next((f for f in self.repo.files if f.rel == path), None)
        if ctx:
            finding.snippet = ctx.line(finding.line).strip()[:160]
        with self._lock:
            self._new_findings.append(finding)
        return "issue recorded"

    def _record_error(self, message: str) -> None:
        with self._lock:
            self.usage.errors.append(message)

    # -- summary ------------------------------------------------------------------------
    def _executive_summary(self, findings: list[Finding]) -> str:
        live = [f for f in findings if f.verdict is not Verdict.FALSE_POSITIVE]
        live.sort(key=lambda f: (-f.severity.rank, -f.confidence))
        digest = [
            {"severity": f.severity.value, "category": f.category.value, "title": f.title,
             "where": f.location, "detail": f.ai_rationale or f.message}
            for f in live[:40]
        ]
        payload = json.dumps({"agent_notes": self._summaries, "top_findings": digest,
                              "total_open_findings": len(live)}, indent=1)
        try:
            response = self.client.messages.create(
                model=self.settings.model,
                max_tokens=2000,
                output_config={"effort": "low"},
                system=SUMMARY_PROMPT,
                messages=[{"role": "user", "content": f"<report_data>\n{payload}\n</report_data>"}],
            )
        except Exception as exc:  # summary is optional polish
            self._record_error(f"summary failed: {type(exc).__name__}: {exc}")
            return ""
        self.usage.add(response)
        if response.stop_reason == "refusal":
            return ""
        return "".join(getattr(b, "text", "") for b in response.content if getattr(b, "type", "") == "text").strip()


def _language_counts(repo: RepoContext) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in repo.files:
        counts[f.language.name] += 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
