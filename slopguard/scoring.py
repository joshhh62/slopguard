"""Turn findings into a 0-100 health score and a letter grade.

Penalties are weighted by severity and confidence, then normalised by code size so a 50k-line
service is not punished for having more surface than a 200-line script. Each category's
penalty is capped so one noisy category cannot hide everything else.
"""

from __future__ import annotations

import math
from collections import defaultdict

from .models import Finding, Severity, Verdict

WEIGHTS = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 0.75,
    Severity.INFO: 0.0,
}
CATEGORY_CAP = 45.0
GRADES = ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F"))


def score_findings(findings: list[Finding], lines_of_code: int) -> tuple[int, str]:
    size_factor = max(1.0, math.sqrt(max(lines_of_code, 1) / 1000))
    per_category: dict[str, float] = defaultdict(float)
    for f in findings:
        if f.verdict is Verdict.FALSE_POSITIVE:
            continue
        per_category[f.category.value] += WEIGHTS[f.severity] * f.confidence
    penalty = sum(min(CATEGORY_CAP, p / size_factor) for p in per_category.values())
    # Any live critical issue caps the grade: a leaked key is never "B" quality.
    has_critical = any(f.severity is Severity.CRITICAL and f.verdict is not Verdict.FALSE_POSITIVE for f in findings)
    score = max(0, round(100 - penalty))
    if has_critical:
        score = min(score, 49)
    grade = next(letter for threshold, letter in GRADES if score >= threshold)
    return score, grade
