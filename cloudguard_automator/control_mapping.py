from __future__ import annotations


CONTROL_MAPPINGS = {
    "IAM_PASSWORD_POLICY_MISSING": ["CIS AWS 1.x", "NIST PR.AC", "AWS Security Pillar IAM"],
    "IAM_PASSWORD_POLICY_WEAK": ["CIS AWS 1.x", "NIST PR.AC", "AWS Security Pillar IAM"],
    "IAM_USER_MFA_DISABLED": ["CIS AWS 1.x", "NIST PR.AC", "AWS Security Pillar IAM"],
    "IAM_STALE_ACCESS_KEY": ["CIS AWS 1.x", "NIST PR.AC", "AWS Security Pillar IAM"],
    "IAM_UNUSED_ACCESS_KEY": ["CIS AWS 1.x", "NIST PR.AC", "AWS Security Pillar IAM"],
    "IAM_USER_DIRECT_ADMIN_POLICY": ["CIS AWS 1.x", "NIST PR.AC", "AWS Security Pillar Least Privilege"],
    "IAM_POLICY_FULL_ADMIN_WILDCARD": ["CIS AWS 1.x", "NIST PR.AC", "AWS Security Pillar Least Privilege"],
    "S3_PUBLIC_ACCESS_BLOCK_MISSING": ["CIS AWS 2.x", "NIST PR.DS", "AWS Security Pillar Data Protection"],
    "S3_PUBLIC_ACCESS_BLOCK_DISABLED": ["CIS AWS 2.x", "NIST PR.DS", "AWS Security Pillar Data Protection"],
    "S3_PUBLIC_ACL": ["CIS AWS 2.x", "NIST PR.DS", "AWS Security Pillar Data Protection"],
    "S3_PUBLIC_BUCKET_POLICY": ["CIS AWS 2.x", "NIST PR.DS", "AWS Security Pillar Data Protection"],
    "S3_DEFAULT_ENCRYPTION_MISSING": ["CIS AWS 2.x", "NIST PR.DS", "AWS Security Pillar Data Protection"],
    "S3_VERSIONING_DISABLED": ["CIS AWS 2.x", "NIST PR.DS", "AWS Security Pillar Data Protection"],
    "S3_ACCESS_LOGGING_DISABLED": ["CIS AWS 2.x", "NIST DE.CM", "AWS Security Pillar Detection"],
    "CLOUDTRAIL_NOT_CONFIGURED": ["CIS AWS 3.x", "NIST DE.CM", "AWS Security Pillar Detection"],
    "CLOUDTRAIL_NOT_LOGGING": ["CIS AWS 3.x", "NIST DE.CM", "AWS Security Pillar Detection"],
    "CLOUDTRAIL_NOT_MULTI_REGION": ["CIS AWS 3.x", "NIST DE.CM", "AWS Security Pillar Detection"],
    "CLOUDTRAIL_LOG_VALIDATION_DISABLED": ["CIS AWS 3.x", "NIST DE.CM", "AWS Security Pillar Detection"],
    "CLOUDTRAIL_KMS_ENCRYPTION_DISABLED": ["CIS AWS 3.x", "NIST PR.DS", "AWS Security Pillar Data Protection"],
    "CLOUDTRAIL_MANAGEMENT_EVENTS_DISABLED": ["CIS AWS 3.x", "NIST DE.CM", "AWS Security Pillar Detection"],
    "EC2_SECURITY_GROUP_PUBLIC_INGRESS": ["CIS AWS 4.x", "NIST PR.AC", "AWS Security Pillar Infrastructure Protection"],
    "EC2_SG_ADMIN_PORT_OPEN": ["CIS AWS 4.x", "NIST PR.AC", "AWS Security Pillar Infrastructure Protection"],
}


def controls_for_check(check_id: str) -> list[str]:
    return CONTROL_MAPPINGS.get(check_id, [])

