import json
import subprocess

from conftest import EXAMPLE_APP, ids, run

from slopguard.cli import main
from slopguard.engine import ScanOptions, scan
from slopguard.models import Category, Finding, Severity, Verdict
from slopguard.reporters import to_html, to_json, to_markdown, to_sarif
from slopguard.scoring import score_findings


def test_inline_suppression(make_repo):
    root = make_repo({
        "a.py": "x = eval(s)  # slopguard: ignore[SEC010] trusted admin console\n"
                "# slopguard: ignore\ny = eval(t)\nz = eval(u)\n",
    })
    result, _ = scan(root)
    lines = [f.line for f in result.findings if f.rule_id == "SEC010"]
    assert lines == [4] and result.stats.suppressed == 2


def test_config_disables_rules_and_overrides_severity(make_repo):
    root = make_repo({
        ".slopguard.toml": 'disable = ["LOOSE001"]\nexclude = ["generated/"]\n[severity]\nSEC010 = "critical"\n',
        "a.py": "# TODO: x\nv = eval(s)\n",
        "generated/b.py": "w = eval(s)\n",
    })
    findings = run(root)
    assert "LOOSE001" not in ids(findings)
    sec = [f for f in findings if f.rule_id == "SEC010"]
    assert [(f.path, f.severity) for f in sec] == [("a.py", Severity.CRITICAL)]


def test_baseline_round_trip(make_repo, tmp_path):
    root = make_repo({"a.py": "v = eval(s)\n"})
    baseline = tmp_path / "baseline.json"
    assert main(["scan", str(root), "-f", "json", "-o", str(tmp_path / "out"), "--write-baseline", str(baseline)]) == 0
    result, _ = scan(root, ScanOptions(baseline=baseline))
    assert not result.findings and result.stats.baselined >= 1


def test_diff_mode_only_reports_changed_lines(make_repo):
    root = make_repo({"a.py": "a = eval(x)\n"})
    git = ["git", "-c", "user.email=t@example.com", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], cwd=root, check=True)
    subprocess.run([*git, "add", "."], cwd=root, check=True)
    subprocess.run([*git, "commit", "-qm", "init"], cwd=root, check=True)
    (root / "a.py").write_text("a = eval(x)\nb = eval(y)\n", encoding="utf-8")
    result, _ = scan(root, ScanOptions(diff_ref="HEAD", only_rules={"SEC010"}))
    assert [f.line for f in result.findings] == [2]


def test_cli_fail_on_and_reports(tmp_path):
    out = tmp_path / "reports"
    code = main(["scan", str(EXAMPLE_APP), "-f", "json,sarif,md,html", "-o", str(out), "--fail-on", "critical"])
    assert code == 1  # the demo app leaks a database password
    data = json.loads((out / "slopguard-report.json").read_text(encoding="utf-8"))
    assert data["grade"] == "F" and data["findings"]
    sarif = json.loads((out / "slopguard.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert "# SlopGuard report" in (out / "slopguard-report.md").read_text(encoding="utf-8")


def test_example_app_covers_every_category():
    result, _ = scan(EXAMPLE_APP)
    cats = {f.category for f in result.findings}
    assert cats == set(Category)
    languages = {f.path.rsplit(".", 1)[-1] for f in result.findings if "." in f.path}
    assert {"py", "js", "go", "java"} <= languages


def test_html_report_cannot_be_broken_out_of(make_repo):
    root = make_repo({"a.py": "x = eval('</script><script>alert(1)</script>')\n"})
    result, _ = scan(root)
    page = to_html(result)
    assert "</script><script>alert(1)" not in page


def test_scoring_ignores_dismissed_and_caps_on_critical():
    def f(sev, verdict=Verdict.UNTRIAGED):
        return Finding("X", "t", Category.SECURITY, sev, "a.py", 1, "m", verdict=verdict, confidence=1.0)

    assert score_findings([], 1000) == (100, "A")
    assert score_findings([f(Severity.HIGH, Verdict.FALSE_POSITIVE)], 1000) == (100, "A")
    score, grade = score_findings([f(Severity.CRITICAL)], 1000)
    assert score <= 49 and grade == "F"


def test_reporters_handle_empty_result(make_repo):
    root = make_repo({"README.md": "hi\n", ".gitignore": "\n"})
    result, _ = scan(root)
    for render in (to_json, to_sarif, to_markdown, to_html):
        assert render(result)


def test_rules_and_explain_commands(capsys):
    assert main(["rules"]) == 0
    assert "SEC001" in capsys.readouterr().out
    assert main(["explain", "slop004"]) == 0
    assert "slopsquatting" in capsys.readouterr().out
    assert main(["explain", "NOPE"]) == 2
