from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Union

from cloudguard_automator.models import Finding, Severity

STALE_ACCESS_KEY_DAYS = 90
ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def scan(session) -> list[Finding]:
    client = session.client("iam")
    findings: list[Finding] = []

    for user in client.list_users().get("Users", []):
        username = user["UserName"]
        findings.extend(_check_console_mfa(client, username))
        findings.extend(_check_access_keys(client, username))
        findings.extend(_check_attached_user_policies(client, username))
        findings.extend(_check_inline_user_policies(client, username))

    findings.extend(_check_account_password_policy(client))
    return findings


def _check_console_mfa(client, username: str) -> list[Finding]:
    try:
        client.get_login_profile(UserName=username)
    except Exception as exc:
        if not _is_client_error(exc):
            raise
        return []

    devices = client.list_mfa_devices(UserName=username).get("MFADevices", [])
    if devices:
        return []

    return [
        Finding(
            check_id="IAM_USER_MFA_DISABLED",
            title=f'IAM user "{username}" has console access without MFA',
            severity=Severity.HIGH,
            resource=username,
            region="global",
            service="iam",
            description="The user can sign in to the AWS console but does not have MFA configured.",
            remediation="Require MFA for console users and prefer role-based access for privileged operations.",
        )
    ]


def _check_access_keys(client, username: str) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    for metadata in client.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
        if metadata.get("Status") != "Active":
            continue

        key_id = metadata["AccessKeyId"]
        create_date = _as_aware_datetime(metadata["CreateDate"])
        key_age_days = (now - create_date).days
        last_used = client.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
        last_used_date = last_used.get("LastUsedDate")

        if last_used_date:
            last_used_age_days = (now - _as_aware_datetime(last_used_date)).days
            if last_used_age_days > STALE_ACCESS_KEY_DAYS:
                findings.append(
                    Finding(
                        check_id="IAM_STALE_ACCESS_KEY",
                        title=f'IAM user "{username}" has an access key unused for {last_used_age_days} days',
                        severity=Severity.MEDIUM,
                        resource=f"{username}/{key_id}",
                        region="global",
                        service="iam",
                        description="Long-lived access keys increase the impact of credential leakage.",
                        remediation="Rotate or delete stale access keys and prefer short-lived role credentials.",
                    )
                )
        elif key_age_days > STALE_ACCESS_KEY_DAYS:
            findings.append(
                Finding(
                    check_id="IAM_UNUSED_ACCESS_KEY",
                    title=f'IAM user "{username}" has an active access key that has never been used',
                    severity=Severity.MEDIUM,
                    resource=f"{username}/{key_id}",
                    region="global",
                    service="iam",
                    description=f"The key is {key_age_days} days old and AWS reports no last-used timestamp.",
                    remediation="Delete unused keys after confirming they are not needed.",
                )
            )

    return findings


def _check_attached_user_policies(client, username: str) -> list[Finding]:
    findings: list[Finding] = []

    for policy in client.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
        policy_name = policy["PolicyName"]
        policy_arn = policy["PolicyArn"]

        if policy_arn == ADMINISTRATOR_ACCESS_ARN:
            findings.append(
                Finding(
                    check_id="IAM_USER_DIRECT_ADMIN_POLICY",
                    title=f'IAM user "{username}" has AdministratorAccess attached directly',
                    severity=Severity.HIGH,
                    resource=username,
                    region="global",
                    service="iam",
                    description="Direct administrative permissions on IAM users increase blast radius and bypass role-based access patterns.",
                    remediation="Move administrative access to a role with MFA-protected assumption conditions.",
                )
            )

        policy_metadata = client.get_policy(PolicyArn=policy_arn)["Policy"]
        version = client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_metadata["DefaultVersionId"])
        if _policy_has_full_admin_access(version["PolicyVersion"]["Document"]):
            findings.append(_wildcard_policy_finding(username, policy_name, "managed"))

    return findings


def _check_inline_user_policies(client, username: str) -> list[Finding]:
    findings: list[Finding] = []

    for policy_name in client.list_user_policies(UserName=username).get("PolicyNames", []):
        policy = client.get_user_policy(UserName=username, PolicyName=policy_name)
        if _policy_has_full_admin_access(policy["PolicyDocument"]):
            findings.append(_wildcard_policy_finding(username, policy_name, "inline"))

    return findings


def _check_account_password_policy(client) -> list[Finding]:
    try:
        policy = client.get_account_password_policy()["PasswordPolicy"]
    except Exception as exc:
        if not _is_client_error(exc):
            raise
        return [
            Finding(
                check_id="IAM_PASSWORD_POLICY_MISSING",
                title="AWS account does not have an IAM password policy",
                severity=Severity.MEDIUM,
                resource="account",
                region="global",
                service="iam",
                description="Without a password policy, console credentials may not meet baseline complexity requirements.",
                remediation="Configure an IAM account password policy with length, complexity, and rotation expectations.",
            )
        ]

    if policy.get("MinimumPasswordLength", 0) >= 14 and policy.get("RequireSymbols") and policy.get("RequireNumbers"):
        return []

    return [
        Finding(
            check_id="IAM_PASSWORD_POLICY_WEAK",
            title="AWS account password policy is weaker than the recommended baseline",
            severity=Severity.LOW,
            resource="account",
            region="global",
            service="iam",
            description="The password policy does not require at least 14 characters, symbols, and numbers.",
            remediation="Strengthen the IAM password policy and consider federated identity instead of long-lived IAM users.",
        )
    ]


def _wildcard_policy_finding(username: str, policy_name: str, policy_type: str) -> Finding:
    return Finding(
        check_id="IAM_POLICY_FULL_ADMIN_WILDCARD",
        title=f'IAM user "{username}" has a {policy_type} policy with full wildcard access',
        severity=Severity.CRITICAL,
        resource=f"{username}/{policy_name}",
        region="global",
        service="iam",
        description='The policy contains an Allow statement with Action "*" and Resource "*".',
        remediation="Replace wildcard permissions with least-privilege actions and resource constraints.",
    )


def _policy_has_full_admin_access(policy_document: Union[dict[str, Any], str]) -> bool:
    policy = _normalize_policy_document(policy_document)
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        if _contains_wildcard(statement.get("Action")) and _contains_wildcard(statement.get("Resource")):
            return True

    return False


def _normalize_policy_document(policy_document: Union[dict[str, Any], str]) -> dict[str, Any]:
    if isinstance(policy_document, str):
        return json.loads(policy_document)
    return policy_document


def _contains_wildcard(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return "*" in value
    return False


def _as_aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_client_error(exc: Exception) -> bool:
    return exc.__class__.__name__ == "ClientError"
