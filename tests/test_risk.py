from cloudguard_automator.models import Finding, Severity
from cloudguard_automator.risk import summarize_findings


def make_finding(severity: Severity) -> Finding:
    return Finding(
        check_id="TEST",
        title="Test finding",
        severity=severity,
        resource="resource",
        region="global",
        service="test",
        description="description",
        remediation="remediation",
    )


def test_summarize_findings_counts_and_scores():
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
        make_finding(Severity.MEDIUM),
    ]

    summary = summarize_findings(findings)

    assert summary["risk_score"] == 47
    assert summary["risk_level"] == "medium"
    assert summary["counts"]["critical"] == 1
    assert summary["counts"]["high"] == 1
    assert summary["counts"]["medium"] == 1

