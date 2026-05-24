from __future__ import annotations

from cloudguard_automator.models import Finding, Severity


def scan(session, region: str) -> list[Finding]:
    client = session.client("cloudtrail")
    findings: list[Finding] = []
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])

    if not trails:
        return [
            Finding(
                check_id="CLOUDTRAIL_NOT_CONFIGURED",
                title=f"CloudTrail is not configured in {region}",
                severity=Severity.HIGH,
                resource="account",
                region=region,
                service="cloudtrail",
                description="No CloudTrail trail was found in this region.",
                remediation="Create a multi-region CloudTrail trail with management events enabled.",
            )
        ]

    for trail in trails:
        name = trail["Name"]
        status = client.get_trail_status(Name=name)
        if not status.get("IsLogging"):
            findings.append(
                Finding(
                    check_id="CLOUDTRAIL_NOT_LOGGING",
                    title=f'CloudTrail trail "{name}" is not logging',
                    severity=Severity.HIGH,
                    resource=name,
                    region=region,
                    service="cloudtrail",
                    description="The trail exists but is not actively logging events.",
                    remediation="Start logging for the trail and verify delivery to the configured S3 bucket.",
                )
            )

        if not trail.get("IsMultiRegionTrail"):
            findings.append(
                Finding(
                    check_id="CLOUDTRAIL_NOT_MULTI_REGION",
                    title=f'CloudTrail trail "{name}" is not multi-region',
                    severity=Severity.MEDIUM,
                    resource=name,
                    region=region,
                    service="cloudtrail",
                    description="Single-region trails can miss activity in other AWS regions.",
                    remediation="Enable multi-region logging for CloudTrail.",
                )
            )

        if not trail.get("LogFileValidationEnabled"):
            findings.append(
                Finding(
                    check_id="CLOUDTRAIL_LOG_VALIDATION_DISABLED",
                    title=f'CloudTrail trail "{name}" has log file validation disabled',
                    severity=Severity.MEDIUM,
                    resource=name,
                    region=region,
                    service="cloudtrail",
                    description="Log file validation helps detect tampering with CloudTrail logs.",
                    remediation="Enable CloudTrail log file validation.",
                )
            )

    return findings

