from cloudguard_automator.demo import demo_findings
from cloudguard_automator.report import render_html


def test_render_html_contains_summary_and_escaped_findings():
    html = render_html(demo_findings())

    assert "<!doctype html>" in html
    assert "CloudGuard Automator Report" in html
    assert "Risk Score" in html
    assert "S3_PUBLIC_ACCESS_BLOCK_DISABLED" in html
    assert "company-backups" in html
    assert "Top Remediation Priorities" in html
    assert "CIS AWS 2.x" in html
