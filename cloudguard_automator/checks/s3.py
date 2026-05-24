from __future__ import annotations

import json
from typing import Any

from cloudguard_automator.models import Finding, Severity

PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def scan(session) -> list[Finding]:
    client = session.client("s3")
    findings: list[Finding] = []

    for bucket in client.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        findings.extend(_check_public_access_block(client, name))
        findings.extend(_check_public_acl(client, name))
        findings.extend(_check_public_policy(client, name))
        findings.extend(_check_encryption(client, name))
        findings.extend(_check_versioning(client, name))
        findings.extend(_check_access_logging(client, name))

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


def _check_public_acl(client, bucket_name: str) -> list[Finding]:
    acl = client.get_bucket_acl(Bucket=bucket_name)
    public_grants = []

    for grant in acl.get("Grants", []):
        grantee_uri = grant.get("Grantee", {}).get("URI")
        permission = grant.get("Permission")
        if grantee_uri in PUBLIC_GRANTEES:
            public_grants.append(permission)

    if not public_grants:
        return []

    return [
        Finding(
            check_id="S3_PUBLIC_ACL",
            title=f'S3 bucket "{bucket_name}" has a public ACL grant',
            severity=Severity.CRITICAL,
            resource=bucket_name,
            region="global",
            service="s3",
            description=f"The bucket ACL grants {', '.join(sorted(public_grants))} permission to a public S3 group.",
            remediation="Remove public ACL grants and rely on bucket policies or IAM identities for access control.",
        )
    ]


def _check_public_policy(client, bucket_name: str) -> list[Finding]:
    try:
        policy_document = client.get_bucket_policy(Bucket=bucket_name)["Policy"]
    except Exception as exc:
        if not _is_client_error(exc):
            raise
        return []

    policy = json.loads(policy_document)
    if not _policy_allows_public_access(policy):
        return []

    return [
        Finding(
            check_id="S3_PUBLIC_BUCKET_POLICY",
            title=f'S3 bucket "{bucket_name}" has a public bucket policy',
            severity=Severity.CRITICAL,
            resource=bucket_name,
            region="global",
            service="s3",
            description='The bucket policy contains an Allow statement with a public principal such as "*".',
            remediation="Remove public principals or add restrictive conditions that limit access to trusted identities.",
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


def _check_access_logging(client, bucket_name: str) -> list[Finding]:
    logging_config = client.get_bucket_logging(Bucket=bucket_name)
    if logging_config.get("LoggingEnabled"):
        return []

    return [
        Finding(
            check_id="S3_ACCESS_LOGGING_DISABLED",
            title=f'S3 bucket "{bucket_name}" does not have server access logging enabled',
            severity=Severity.LOW,
            resource=bucket_name,
            region="global",
            service="s3",
            description="Server access logging can help investigate unexpected access to sensitive buckets.",
            remediation="Enable S3 server access logging or ensure equivalent object-level data events are captured.",
        )
    ]


def _policy_allows_public_access(policy: dict[str, Any]) -> bool:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        if _principal_is_public(statement.get("Principal")) and not _has_restrictive_condition(statement):
            return True

    return False


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True

    if isinstance(principal, dict):
        aws_principal = principal.get("AWS")
        if aws_principal == "*":
            return True
        if isinstance(aws_principal, list) and "*" in aws_principal:
            return True

    return False


def _has_restrictive_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("Condition")
    if not condition:
        return False

    condition_text = json.dumps(condition)
    restrictive_keys = (
        "aws:PrincipalArn",
        "aws:PrincipalAccount",
        "aws:SourceArn",
        "aws:SourceAccount",
        "aws:SourceVpc",
        "aws:SourceVpce",
    )
    return any(key in condition_text for key in restrictive_keys)


def _is_client_error(exc: Exception) -> bool:
    return exc.__class__.__name__ == "ClientError"
