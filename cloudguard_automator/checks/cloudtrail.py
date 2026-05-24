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

        if not trail.get("KmsKeyId"):
            findings.append(
                Finding(
                    check_id="CLOUDTRAIL_KMS_ENCRYPTION_DISABLED",
                    title=f'CloudTrail trail "{name}" is not encrypted with a customer managed KMS key',
                    severity=Severity.MEDIUM,
                    resource=name,
                    region=region,
                    service="cloudtrail",
                    description="CloudTrail log files are not configured to use a customer managed KMS key.",
                    remediation="Configure CloudTrail to encrypt logs with a customer managed KMS key and restrict key access.",
                )
            )

        if not _management_events_enabled(client, name):
            findings.append(
                Finding(
                    check_id="CLOUDTRAIL_MANAGEMENT_EVENTS_DISABLED",
                    title=f'CloudTrail trail "{name}" does not capture management events',
                    severity=Severity.HIGH,
                    resource=name,
                    region=region,
                    service="cloudtrail",
                    description="Management events record control-plane activity such as IAM, EC2, and S3 API changes.",
                    remediation="Enable read and write management events for the trail.",
                )
            )

    return findings


def _management_events_enabled(client, trail_name: str) -> bool:
    selectors = client.get_event_selectors(TrailName=trail_name)

    for selector in selectors.get("EventSelectors", []):
        if selector.get("IncludeManagementEvents"):
            return True

    for selector in selectors.get("AdvancedEventSelectors", []):
        for field_selector in selector.get("FieldSelectors", []):
            if field_selector.get("Field") == "eventCategory" and "Management" in field_selector.get("Equals", []):
                return True

    return False
