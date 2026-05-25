from cloudguard_automator.control_mapping import controls_for_check
from cloudguard_automator.demo import demo_findings


def test_controls_for_check_returns_framework_refs():
    controls = controls_for_check("S3_PUBLIC_ACCESS_BLOCK_DISABLED")

    assert "CIS AWS 2.x" in controls
    assert "NIST PR.DS" in controls


def test_finding_serialization_includes_control_refs():
    finding = demo_findings()[0]
    payload = finding.to_dict()

    assert "control_refs" in payload
    assert "AWS Security Pillar Data Protection" in payload["control_refs"]
