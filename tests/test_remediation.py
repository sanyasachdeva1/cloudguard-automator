from cloudguard_automator.demo import demo_findings
from cloudguard_automator.remediation import build_plan, render_plan_markdown


def test_build_plan_maps_demo_findings_to_steps():
    steps = build_plan(demo_findings())
    action_types = {step.action_type for step in steps}

    assert len(steps) == 3
    assert "aws-cli" in action_types
    assert "manual-review" in action_types


def test_render_plan_markdown_includes_commands():
    steps = build_plan(demo_findings())
    markdown = render_plan_markdown(steps)

    assert "# CloudGuard Automator Remediation Plan" in markdown
    assert "aws s3api put-public-access-block" in markdown
    assert "Review IAM finding" in markdown
