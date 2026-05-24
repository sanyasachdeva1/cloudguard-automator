from __future__ import annotations

from collections import Counter

from cloudguard_automator.models import Finding, Severity


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def summarize_findings(findings: list[Finding]) -> dict[str, object]:
    counts = Counter(finding.severity.value for finding in findings)
    raw_score = sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings)
    risk_score = min(raw_score, 100)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level(risk_score),
        "total_findings": len(findings),
        "counts": {
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "info": counts["info"],
        },
    }


def risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "informational"

