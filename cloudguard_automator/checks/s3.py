from __future__ import annotations

from cloudguard_automator.models import Finding, Severity


def scan(session) -> list[Finding]:
    client = session.client("s3")
    findings: list[Finding] = []

    for bucket in client.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        findings.extend(_check_public_access_block(client, name))
        findings.extend(_check_encryption(client, name))
        findings.extend(_check_versioning(client, name))

    return findings


def _check_public_access_block(client, bucket_name: str) -> list[Finding]:
    try:
        config = client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    except Exception as exc:
        if not _is_client_error(exc):
            raise
        return [
            Finding(
                check_id="S3_PUBLIC_ACCESS_BLOCK_MISSING",
                title=f'S3 bucket "{bucket_name}" is missing public access block configuration',
                severity=Severity.HIGH,
                resource=bucket_name,
                region="global",
                service="s3",
                description="The bucket does not have an explicit Block Public Access configuration.",
                remediation="Enable all S3 Block Public Access settings for the bucket.",
            )
        ]

    required_flags = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    if all(config.get(flag) for flag in required_flags):
        return []

    return [
        Finding(
            check_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            title=f'S3 bucket "{bucket_name}" does not block all public access paths',
            severity=Severity.HIGH,
            resource=bucket_name,
            region="global",
            service="s3",
            description="One or more S3 Block Public Access settings are disabled.",
            remediation="Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.",
        )
    ]


def _check_encryption(client, bucket_name: str) -> list[Finding]:
    try:
        client.get_bucket_encryption(Bucket=bucket_name)
        return []
    except Exception as exc:
        if not _is_client_error(exc):
            raise
        return [
            Finding(
                check_id="S3_DEFAULT_ENCRYPTION_MISSING",
                title=f'S3 bucket "{bucket_name}" does not define default encryption',
                severity=Severity.MEDIUM,
                resource=bucket_name,
                region="global",
                service="s3",
                description="Objects uploaded to the bucket may not be encrypted by default.",
                remediation="Enable default encryption with SSE-S3 or SSE-KMS.",
            )
        ]


def _check_versioning(client, bucket_name: str) -> list[Finding]:
    versioning = client.get_bucket_versioning(Bucket=bucket_name)
    if versioning.get("Status") == "Enabled":
        return []

    return [
        Finding(
            check_id="S3_VERSIONING_DISABLED",
            title=f'S3 bucket "{bucket_name}" does not have versioning enabled',
            severity=Severity.LOW,
            resource=bucket_name,
            region="global",
            service="s3",
            description="Versioning helps recover from accidental deletion, overwrite, and some ransomware scenarios.",
            remediation="Enable S3 bucket versioning where retention and recovery requirements apply.",
        )
    ]


def _is_client_error(exc: Exception) -> bool:
    return exc.__class__.__name__ == "ClientError"
