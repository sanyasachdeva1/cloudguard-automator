# AWS Permissions

CloudGuard Automator is designed as a read-only scanner. For live AWS scans, use a dedicated audit role or profile instead of administrator credentials.

## Recommended Approach

Use one of these managed policies for a sandbox or portfolio demo:

- `SecurityAudit`
- `ViewOnlyAccess`

For a more production-like setup, create a dedicated audit role with only the read permissions needed by the enabled checks.

## Services Read By The Scanner

The current live scanner uses read-only APIs across:

- IAM
- S3
- CloudTrail
- EC2 security groups

## Example Least-Privilege Starting Point

This policy is a starting point for live scans. Adjust it for your organization, regions, and service coverage.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccessKeyLastUsed",
        "iam:GetLoginProfile",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListMFADevices",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "s3:GetBucketAcl",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:ListAllMyBuckets",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

## Safety Notes

- Do not run the scanner with long-lived administrator credentials.
- Prefer AWS SSO, a dedicated audit role, or temporary credentials.
- Remediation output is dry-run by default; review generated commands before applying any changes.

