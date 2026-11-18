"""Machine-readable reports: JSON (stable schema) and SARIF 2.1.0 (GitHub code scanning)."""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..models import ScanResult, Severity, Verdict
from ..rules import all_rules

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                      Severity.LOW: "3.0", Severity.INFO: "0.0"}


def to_json(result: ScanResult) -> str:
    payload: dict[str, Any] = {
        "tool": {"name": "slopguard", "version": __version__},
        "root": result.root,
        "score": result.score,
        "grade": result.grade,
        "stats": {k: v for k, v in vars(result.stats).items()},
        "counts": {"by_severity": result.by_severity(), "by_category": result.by_category()},
        "ai": {"summary": result.ai_summary, "usage": result.ai_usage} if result.ai_usage else None,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_sarif(result: ScanResult) -> str:
    rules_meta = {r.meta.id: r.meta for r in all_rules()}
    used = sorted({f.rule_id for f in result.findings})
    sarif_rules = []
    for rule_id in used:
        meta = rules_meta.get(rule_id)
        sample = next(f for f in result.findings if f.rule_id == rule_id)
        sarif_rules.append({
            "id": rule_id,
            "name": (meta.title if meta else sample.title).replace(" ", ""),
            "shortDescription": {"text": meta.title if meta else sample.title},
            "fullDescription": {"text": meta.description if meta else sample.message},
            "help": {"text": meta.fix if meta else sample.fix},
            "properties": {"tags": [sample.category.value], "security-severity": _SECURITY_SEVERITY[sample.severity]},
        })
    results = []
    for f in result.findings:
        if f.verdict is Verdict.FALSE_POSITIVE:
            continue
        location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": f.path or "."}}}
        if f.line:
            location["physicalLocation"]["region"] = {"startLine": f.line}
        message = f.message + (f"\n\nAI triage: {f.ai_rationale}" if f.ai_rationale else "") + f"\n\nFix: {f.fix}"
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": message},
            "locations": [location],
            "partialFingerprints": {"slopguard/v1": f.fingerprint},
            "properties": {"category": f.category.value, "confidence": f.confidence, "verdict": f.verdict.value},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SlopGuard", "version": __version__,
                                "informationUri": "https://github.com/joshhh62/slopguard", "rules": sarif_rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
