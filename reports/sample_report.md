# CloudGuard Automator Report

## Executive Summary

- Risk score: **55/100**
- Risk level: **medium**
- Total findings: **3**

## Severity Counts

- Critical: 1
- High: 2
- Medium: 0
- Low: 0
- Info: 0

## Findings

### HIGH: S3 bucket "company-backups" does not block public access

- Check ID: `S3_PUBLIC_ACCESS_BLOCK_DISABLED`
- Service: `s3`
- Resource: `company-backups`
- Region: `global`
- Control refs: `CIS AWS 2.x`, `NIST PR.DS`, `AWS Security Pillar Data Protection`
- Description: The bucket does not have all S3 Block Public Access controls enabled.
- Remediation: Enable S3 Block Public Access for the bucket and review the bucket policy.

### HIGH: IAM user "backup-admin" has console access without MFA

- Check ID: `IAM_USER_MFA_DISABLED`
- Service: `iam`
- Resource: `backup-admin`
- Region: `global`
- Control refs: `CIS AWS 1.x`, `NIST PR.AC`, `AWS Security Pillar IAM`
- Description: Console users without MFA are more exposed to credential theft and account takeover.
- Remediation: Require MFA for the user or migrate access to a role-based workflow.

### CRITICAL: Security group exposes SSH to the internet

- Check ID: `EC2_SG_ADMIN_PORT_OPEN`
- Service: `ec2`
- Resource: `sg-0123456789abcdef0`
- Region: `us-east-1`
- Control refs: `CIS AWS 4.x`, `NIST PR.AC`, `AWS Security Pillar Infrastructure Protection`
- Description: Port 22 is reachable from 0.0.0.0/0.
- Remediation: Restrict SSH access to trusted IP ranges or use AWS Systems Manager Session Manager.
