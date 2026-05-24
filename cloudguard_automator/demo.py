from __future__ import annotations

from cloudguard_automator.models import Finding, Severity


def demo_findings() -> list[Finding]:
    return [
        Finding(
            check_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            title='S3 bucket "company-backups" does not block public access',
            severity=Severity.HIGH,
            resource="company-backups",
            region="global",
            service="s3",
            description="The bucket does not have all S3 Block Public Access controls enabled.",
            remediation="Enable S3 Block Public Access for the bucket and review the bucket policy.",
        ),
        Finding(
            check_id="IAM_USER_MFA_DISABLED",
            title='IAM user "backup-admin" has console access without MFA',
            severity=Severity.HIGH,
            resource="backup-admin",
            region="global",
            service="iam",
            description="Console users without MFA are more exposed to credential theft and account takeover.",
            remediation="Require MFA for the user or migrate access to a role-based workflow.",
        ),
        Finding(
            check_id="EC2_SG_ADMIN_PORT_OPEN",
            title="Security group exposes SSH to the internet",
            severity=Severity.CRITICAL,
            resource="sg-0123456789abcdef0",
            region="us-east-1",
            service="ec2",
            description="Port 22 is reachable from 0.0.0.0/0.",
            remediation="Restrict SSH access to trusted IP ranges or use AWS Systems Manager Session Manager.",
        ),
    ]

