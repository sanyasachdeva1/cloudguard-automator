from __future__ import annotations

from cloudguard_automator.models import Finding, Severity


def scan(session) -> list[Finding]:
    client = session.client("iam")
    findings: list[Finding] = []

    for user in client.list_users().get("Users", []):
        username = user["UserName"]
        findings.extend(_check_console_mfa(client, username))

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


def _is_client_error(exc: Exception) -> bool:
    return exc.__class__.__name__ == "ClientError"
