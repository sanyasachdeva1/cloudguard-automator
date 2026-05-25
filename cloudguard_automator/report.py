from __future__ import annotations

import json
from html import escape
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


def render_html(findings: list[Finding]) -> str:
    summary = summarize_findings(findings)
    counts = summary["counts"]
    finding_rows = "\n".join(_render_finding_card(finding) for finding in findings)
    if not finding_rows:
        finding_rows = '<p class="empty">No findings detected.</p>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CloudGuard Automator Report</title>
  <style>
    :root {{
      --bg: #f7f9fb;
      --panel: #ffffff;
      --ink: #16202a;
      --muted: #5c6b7a;
      --line: #d8e0e8;
      --critical: #b42318;
      --high: #c2410c;
      --medium: #b7791f;
      --low: #2f6f4e;
      --info: #2f5f98;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.5;
    }}
    main {{
      width: min(1120px, calc(100% - 32px));
      margin: 32px auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      gap: 24px;
      align-items: flex-start;
      border-bottom: 1px solid var(--line);
      padding-bottom: 20px;
      margin-bottom: 24px;
    }}
    h1, h2, h3, p {{ margin-top: 0; }}
    h1 {{ font-size: 32px; margin-bottom: 8px; }}
    h2 {{ font-size: 20px; margin-bottom: 12px; }}
    h3 {{ font-size: 17px; margin-bottom: 10px; }}
    .muted {{ color: var(--muted); }}
    .score {{
      min-width: 180px;
      padding: 16px;
      border: 1px solid var(--line);
      background: var(--panel);
      text-align: center;
    }}
    .score strong {{ display: block; font-size: 34px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }}
    .metric, .finding {{
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 16px;
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 13px; }}
    .metric strong {{ display: block; font-size: 24px; }}
    .finding {{ margin-bottom: 12px; }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      color: #ffffff;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
      margin-bottom: 10px;
    }}
    .critical {{ background: var(--critical); }}
    .high {{ background: var(--high); }}
    .medium {{ background: var(--medium); }}
    .low {{ background: var(--low); }}
    .info {{ background: var(--info); }}
    dl {{
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 6px 12px;
      margin: 0;
    }}
    dt {{ color: var(--muted); font-weight: 700; }}
    dd {{ margin: 0; }}
    code {{
      background: #edf2f7;
      padding: 2px 5px;
      border-radius: 4px;
    }}
    .empty {{
      background: var(--panel);
      border: 1px solid var(--line);
      padding: 16px;
    }}
    @media (max-width: 760px) {{
      header {{ display: block; }}
      .score {{ margin-top: 16px; text-align: left; }}
      .grid {{ grid-template-columns: repeat(2, 1fr); }}
      dl {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>CloudGuard Automator Report</h1>
        <p class="muted">AWS security posture findings across IAM, S3, CloudTrail, and EC2 security groups.</p>
      </div>
      <div class="score">
        <span class="muted">Risk Score</span>
        <strong>{summary["risk_score"]}/100</strong>
        <span>{escape(str(summary["risk_level"]).title())}</span>
      </div>
    </header>

    <section aria-labelledby="severity-counts">
      <h2 id="severity-counts">Severity Counts</h2>
      <div class="grid">
        {_render_metric("Critical", counts["critical"])}
        {_render_metric("High", counts["high"])}
        {_render_metric("Medium", counts["medium"])}
        {_render_metric("Low", counts["low"])}
        {_render_metric("Info", counts["info"])}
      </div>
    </section>

    <section aria-labelledby="findings">
      <h2 id="findings">Findings</h2>
      {finding_rows}
    </section>
  </main>
</body>
</html>
"""


def _render_metric(label: str, value: int) -> str:
    return f'<div class="metric"><span>{escape(label)}</span><strong>{value}</strong></div>'


def _render_finding_card(finding: Finding) -> str:
    severity = escape(finding.severity.value)
    return f"""<article class="finding">
  <span class="badge {severity}">{severity}</span>
  <h3>{escape(finding.title)}</h3>
  <dl>
    <dt>Check ID</dt><dd><code>{escape(finding.check_id)}</code></dd>
    <dt>Service</dt><dd><code>{escape(finding.service)}</code></dd>
    <dt>Resource</dt><dd><code>{escape(finding.resource)}</code></dd>
    <dt>Region</dt><dd><code>{escape(finding.region)}</code></dd>
    <dt>Description</dt><dd>{escape(finding.description)}</dd>
    <dt>Remediation</dt><dd>{escape(finding.remediation)}</dd>
  </dl>
</article>"""


def write_report(content: str, output_path: str | None) -> None:
    if not output_path:
        print(content)
        return

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Wrote report to {path}")
