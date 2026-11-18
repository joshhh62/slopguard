"""The triage loop is tested against a scripted fake client - no network, no API key."""

from __future__ import annotations

import itertools
from types import SimpleNamespace

import pytest

from slopguard.agent import AgentSettings, TriageAgent
from slopguard.agent.tools import RepoTools, ToolError
from slopguard.engine import scan
from slopguard.models import Verdict


def tool_use(name, **inputs):
    return SimpleNamespace(type="tool_use", id=f"tu_{next(_ids)}", name=name, input=inputs)


def text(value):
    return SimpleNamespace(type="text", text=value)


def response(*blocks, stop="tool_use"):
    usage = SimpleNamespace(input_tokens=1000, output_tokens=200, cache_read_input_tokens=500)
    return SimpleNamespace(content=list(blocks), stop_reason=stop, usage=usage)


_ids = itertools.count()


class FakeClient:
    """Plays back scripted responses and records every request it receives."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        self.messages = self

    def create(self, **kwargs):
        # snapshot: the agent keeps appending to the same list after the call, as the real SDK allows
        self.requests.append({**kwargs, "messages": list(kwargs["messages"])})
        if not self.script:
            return response(text("Summary: fix the eval first."), stop="end_turn")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def repo_with_findings(make_repo):
    root = make_repo({
        "app.py": "import os\n\n\ndef run(cmd):\n    return eval(cmd)\n\n\nADMIN = os.system('uptime')\n",
    })
    result, repo = scan(root, None)
    return result, repo


def test_agent_confirms_dismisses_and_adds_findings(repo_with_findings):
    result, repo = repo_with_findings
    candidates = {f.rule_id: f for f in result.findings if f.path}
    assert {"SEC010", "SEC011"} <= set(candidates)

    agent = TriageAgent(repo, AgentSettings(concurrency=1), client=None)
    batches = agent._plan_batches(result.findings)
    id_of = {f.rule_id: fid for fid, f in batches[0]}

    script = [
        response(tool_use("read_file", path="app.py", start_line=1, end_line=20),
                 tool_use("search_code", pattern=r"run\(")),
        response(
            tool_use("record_verdict", finding_id=id_of["SEC010"], verdict="confirmed", severity="critical",
                     rationale="cmd comes straight from callers", fix="use ast.literal_eval"),
            tool_use("record_verdict", finding_id=id_of["SEC011"], verdict="false_positive", severity="low",
                     rationale="constant command, no user input", fix="use subprocess.run(['uptime'])"),
            tool_use("report_issue", path="app.py", line=4, category="gap", severity="medium",
                     title="No input validation on run()", explanation="cmd is never validated", fix="validate"),
        ),
        response(*[tool_use("record_verdict", finding_id=fid, verdict="needs_review", severity=f.severity.value,
                            rationale="r", fix="f")
                   for fid, f in batches[0] if f.rule_id not in {"SEC010", "SEC011"}],
                 tool_use("finish", summary="eval is the real risk")),
    ]
    client = FakeClient(script)
    agent._client = client
    outcome = agent.run(result.findings)

    by_rule = {f.rule_id: f for f in outcome.findings}
    assert by_rule["SEC010"].verdict is Verdict.CONFIRMED and by_rule["SEC010"].severity.value == "critical"
    assert by_rule["SEC011"].verdict is Verdict.FALSE_POSITIVE
    assert by_rule["AI-GAP"].source == "ai" and by_rule["AI-GAP"].snippet == "def run(cmd):"
    assert outcome.summary == "Summary: fix the eval first."
    assert outcome.usage["requests"] == 4 and outcome.usage["tool_calls"] >= 6
    assert outcome.usage["estimated_cost_usd"] > 0

    first = client.requests[0]
    assert first["model"] == "claude-opus-5-5"
    assert first["system"][0]["cache_control"] == {"type": "ephemeral"}
    # tool results are returned in a single user message, in order, with matching ids
    tool_results = client.requests[1]["messages"][-1]["content"]
    assert [r["type"] for r in tool_results] == ["tool_result", "tool_result"]
    assert "eval(cmd)" in tool_results[0]["content"]


def test_api_failure_keeps_static_results(repo_with_findings):
    result, repo = repo_with_findings
    client = FakeClient([RuntimeError("connection reset")] * 3)
    outcome = TriageAgent(repo, AgentSettings(concurrency=1), client=client).run(result.findings)
    assert len(outcome.findings) == len(result.findings)
    assert all(f.verdict is Verdict.UNTRIAGED for f in outcome.findings)
    assert any("connection reset" in e for e in outcome.usage["errors"])


def test_refusal_and_bad_tool_input_are_handled(repo_with_findings):
    result, repo = repo_with_findings
    client = FakeClient([
        response(tool_use("record_verdict", finding_id="F999", verdict="confirmed", severity="high",
                          rationale="x", fix="y"),
                 tool_use("read_file", path="../../etc/passwd", start_line=1, end_line=5)),
        response(stop="refusal"),
    ])
    outcome = TriageAgent(repo, AgentSettings(concurrency=1), client=client).run(result.findings)
    results = client.requests[1]["messages"][-1]["content"]
    assert all(r["is_error"] for r in results)
    assert any("refusal" in e for e in outcome.usage["errors"])


def test_tools_are_sandboxed(repo_with_findings):
    _, repo = repo_with_findings
    tools = RepoTools(repo)
    with pytest.raises(ToolError):
        tools.read_file("../outside.py", 1, 10)
    with pytest.raises(ToolError):
        tools.search_code("(unclosed")
    assert "eval(cmd)" in tools.read_file("app.py", 1, 999)
