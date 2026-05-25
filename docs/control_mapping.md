# Control Mapping

CloudGuard Automator is not a compliance scanner, but its checks map to common cloud security control themes. This table documents the intended relationship between implemented checks and widely used frameworks.

| Check area | Example checks | Control mapping | Why it matters |
| --- | --- | --- | --- |
| IAM MFA and credential hygiene | `IAM_USER_MFA_DISABLED`, `IAM_STALE_ACCESS_KEY`, `IAM_UNUSED_ACCESS_KEY` | CIS AWS Foundations 1.x, NIST CSF PR.AC, AWS Well-Architected Security Pillar identity and access management | Weak or long-lived credentials increase the likelihood and impact of account compromise. |
| IAM excessive permissions | `IAM_USER_DIRECT_ADMIN_POLICY`, `IAM_POLICY_FULL_ADMIN_WILDCARD` | CIS AWS Foundations 1.x, NIST CSF PR.AC, AWS Well-Architected least privilege guidance | Broad permissions increase blast radius when an identity is misused or compromised. |
| S3 public exposure | `S3_PUBLIC_ACL`, `S3_PUBLIC_BUCKET_POLICY`, `S3_PUBLIC_ACCESS_BLOCK_DISABLED` | CIS AWS Foundations 2.x, NIST CSF PR.DS, AWS Well-Architected data protection guidance | Public storage can expose sensitive files, backups, logs, or application data. |
| S3 data protection | `S3_DEFAULT_ENCRYPTION_MISSING`, `S3_VERSIONING_DISABLED`, `S3_ACCESS_LOGGING_DISABLED` | CIS AWS Foundations 2.x, NIST CSF PR.DS and DE.CM, AWS Well-Architected data protection and detection guidance | Encryption, recovery controls, and access visibility reduce the impact of data exposure or destructive changes. |
| CloudTrail logging baseline | `CLOUDTRAIL_NOT_CONFIGURED`, `CLOUDTRAIL_NOT_LOGGING`, `CLOUDTRAIL_NOT_MULTI_REGION`, `CLOUDTRAIL_LOG_VALIDATION_DISABLED`, `CLOUDTRAIL_KMS_ENCRYPTION_DISABLED`, `CLOUDTRAIL_MANAGEMENT_EVENTS_DISABLED` | CIS AWS Foundations 3.x, NIST CSF DE.CM and RS.AN, AWS Well-Architected detection guidance | Missing or incomplete logs reduce investigation, detection, and incident response visibility. |
| Network exposure | `EC2_SECURITY_GROUP_PUBLIC_INGRESS` | CIS AWS Foundations 4.x, NIST CSF PR.AC, AWS Well-Architected infrastructure protection guidance | Public administrative or database ports increase exposure to brute force, exploitation, and unauthorized access attempts. |

## Notes

- The mappings are intentionally lightweight and are meant to explain security relevance, not certify compliance.
- Framework section numbers can change over time; validate exact control IDs before using this project for formal audit work.
- Future versions can add machine-readable mappings to each finding.

