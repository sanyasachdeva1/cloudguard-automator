from __future__ import annotations

from cloudguard_automator.checks import cloudtrail, iam, s3, security_groups
from cloudguard_automator.demo import demo_findings
from cloudguard_automator.models import Finding


def run_scan(profile: str | None, regions: list[str], demo: bool = False) -> list[Finding]:
    if demo:
        return demo_findings()

    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 is required for live AWS scans. Run `pip install -e .`.") from exc

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    findings: list[Finding] = []
    findings.extend(iam.scan(session))
    findings.extend(s3.scan(session))

    for region in regions:
        regional_session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
        findings.extend(cloudtrail.scan(regional_session, region))
        findings.extend(security_groups.scan(regional_session, region))

    return findings

