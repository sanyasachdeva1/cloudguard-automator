from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from cloudguard_automator.models import Finding


@dataclass(frozen=True)
class RemediationStep:
    check_id: str
    resource: str
    title: str
    risk: str
    action_type: str
    command: str
    notes: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def build_plan(findings: list[Finding]) -> list[RemediationStep]:
    return [_step_for_finding(finding) for finding in findings]


def render_plan_json(steps: list[RemediationStep]) -> str:
    return json.dumps({"steps": [step.to_dict() for step in steps]}, indent=2)


def render_plan_markdown(steps: list[RemediationStep]) -> str:
    lines = ["# CloudGuard Automator Remediation Plan", "", "Mode: dry-run", ""]

    if not steps:
        lines.append("No remediation steps generated.")
        return "\n".join(lines)

    for step in steps:
        lines.extend(
            [
                f"## {step.title}",
                "",
                f"- Check ID: `{step.check_id}`",
                f"- Resource: `{step.resource}`",
                f"- Risk: {step.risk}",
                f"- Action type: `{step.action_type}`",
                f"- Notes: {step.notes}",
                "",
                "```bash",
                step.command,
                "```",
                "",
            ]
        )

    return "\n".join(lines)


def _step_for_finding(finding: Finding) -> RemediationStep:
    builder = REMEDIATION_BUILDERS.get(finding.check_id, _manual_review_step)
    return builder(finding)


def _s3_public_access_block_step(finding: Finding) -> RemediationStep:
    return RemediationStep(
        check_id=finding.check_id,
        resource=finding.resource,
        title=f"Enable S3 Block Public Access for {finding.resource}",
        risk=finding.severity.value,
        action_type="aws-cli",
        command=(
            "aws s3api put-public-access-block "
            f"--bucket {finding.resource} "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        notes="Safe candidate for automation after confirming the bucket is not intentionally public.",
    )


def _s3_encryption_step(finding: Finding) -> RemediationStep:
    return RemediationStep(
        check_id=finding.check_id,
        resource=finding.resource,
        title=f"Enable default encryption for {finding.resource}",
        risk=finding.severity.value,
        action_type="aws-cli",
        command=(
            "aws s3api put-bucket-encryption "
            f"--bucket {finding.resource} "
            "--server-side-encryption-configuration "
            "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
        ),
        notes="Uses SSE-S3 by default; use SSE-KMS when key-level access control is required.",
    )


def _s3_versioning_step(finding: Finding) -> RemediationStep:
    return RemediationStep(
        check_id=finding.check_id,
        resource=finding.resource,
        title=f"Enable versioning for {finding.resource}",
        risk=finding.severity.value,
        action_type="aws-cli",
        command=f"aws s3api put-bucket-versioning --bucket {finding.resource} --versioning-configuration Status=Enabled",
        notes="Confirm lifecycle rules and storage cost expectations before enabling broadly.",
    )


def _iam_manual_step(finding: Finding) -> RemediationStep:
    return RemediationStep(
        check_id=finding.check_id,
        resource=finding.resource,
        title=f"Review IAM remediation for {finding.resource}",
        risk=finding.severity.value,
        action_type="manual-review",
        command=f"# Review IAM finding: {finding.title}",
        notes="IAM changes can break access paths; validate ownership and least-privilege requirements before applying.",
    )


def _cloudtrail_logging_step(finding: Finding) -> RemediationStep:
    return RemediationStep(
        check_id=finding.check_id,
        resource=finding.resource,
        title=f"Start CloudTrail logging for {finding.resource}",
        risk=finding.severity.value,
        action_type="aws-cli",
        command=f"aws cloudtrail start-logging --name {finding.resource}",
        notes="Verify S3 delivery, KMS permissions, and organization trail ownership after starting logging.",
    )


def _security_group_manual_step(finding: Finding) -> RemediationStep:
    return RemediationStep(
        check_id=finding.check_id,
        resource=finding.resource,
        title=f"Restrict public ingress for {finding.resource}",
        risk=finding.severity.value,
        action_type="manual-review",
        command=f"# Review inbound rules for {finding.resource} and replace public CIDRs with trusted ranges",
        notes="Network rule removal is intentionally manual in this phase to avoid locking out valid access.",
    )


def _manual_review_step(finding: Finding) -> RemediationStep:
    return RemediationStep(
        check_id=finding.check_id,
        resource=finding.resource,
        title=f"Review remediation for {finding.resource}",
        risk=finding.severity.value,
        action_type="manual-review",
        command=f"# {finding.remediation}",
        notes="No automated remediation template exists yet for this finding.",
    )


REMEDIATION_BUILDERS = {
    "S3_PUBLIC_ACCESS_BLOCK_DISABLED": _s3_public_access_block_step,
    "S3_PUBLIC_ACCESS_BLOCK_MISSING": _s3_public_access_block_step,
    "S3_DEFAULT_ENCRYPTION_MISSING": _s3_encryption_step,
    "S3_VERSIONING_DISABLED": _s3_versioning_step,
    "IAM_USER_MFA_DISABLED": _iam_manual_step,
    "IAM_STALE_ACCESS_KEY": _iam_manual_step,
    "IAM_UNUSED_ACCESS_KEY": _iam_manual_step,
    "IAM_USER_DIRECT_ADMIN_POLICY": _iam_manual_step,
    "IAM_POLICY_FULL_ADMIN_WILDCARD": _iam_manual_step,
    "CLOUDTRAIL_NOT_LOGGING": _cloudtrail_logging_step,
    "EC2_SECURITY_GROUP_PUBLIC_INGRESS": _security_group_manual_step,
    "EC2_SG_ADMIN_PORT_OPEN": _security_group_manual_step,
}
