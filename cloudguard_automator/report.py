from __future__ import annotations

import json
from pathlib import Path

from cloudguard_automator.models import Finding
from cloudguard_automator.risk import summarize_findings


def render_json(findings: list[Finding]) -> str:
    payload = {
        "summary": summarize_findings(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2)


def render_markdown(findings: list[Finding]) -> str:
    summary = summarize_findings(findings)
    lines = [
        "# CloudGuard Automator Report",
        "",
        "## Executive Summary",
        "",
        f"- Risk score: **{summary['risk_score']}/100**",
        f"- Risk level: **{summary['risk_level']}**",
        f"- Total findings: **{summary['total_findings']}**",
        "",
        "## Severity Counts",
        "",
    ]

    counts = summary["counts"]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity.title()}: {counts[severity]}")

    lines.extend(["", "## Findings", ""])

    if not findings:
        lines.append("No findings detected.")
        return "\n".join(lines)

    for finding in findings:
        lines.extend(
            [
                f"### {finding.severity.value.upper()}: {finding.title}",
                "",
                f"- Check ID: `{finding.check_id}`",
                f"- Service: `{finding.service}`",
                f"- Resource: `{finding.resource}`",
                f"- Region: `{finding.region}`",
                f"- Description: {finding.description}",
                f"- Remediation: {finding.remediation}",
                "",
            ]
        )

    return "\n".join(lines)


def write_report(content: str, output_path: str | None) -> None:
    if not output_path:
        print(content)
        return

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Wrote report to {path}")

