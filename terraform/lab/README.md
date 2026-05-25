# Vulnerable AWS Lab

This Terraform lab creates a small set of intentionally insecure AWS resources so CloudGuard Automator can be demonstrated end to end.

## Warning

This lab intentionally creates insecure resources. Use only in a sandbox AWS account. Do not deploy it in a production account. Destroy it as soon as you finish testing.

## What It Creates

- S3 bucket with Block Public Access disabled
- Public S3 bucket policy for object reads
- S3 bucket without default encryption
- S3 bucket without versioning
- Security group exposing SSH and PostgreSQL to the internet
- IAM user with an inline wildcard admin policy

CloudTrail is intentionally not created by this lab, so the scanner can report missing or incomplete logging baselines in accounts without CloudTrail already configured.

## Requirements

- Terraform
- AWS credentials for a sandbox account
- Permissions to create S3, IAM, and EC2 security group resources

## Usage

```bash
cd terraform/lab
terraform init
terraform plan
terraform apply
```

Run the scanner from the repository root:

```bash
cloudguard scan --profile default --regions us-east-1 --format markdown --output reports/lab_scan.md
cloudguard remediate --profile default --regions us-east-1 --dry-run --format markdown --output reports/lab_remediation.md
```

Destroy the lab:

```bash
terraform destroy
```

## Notes

Some AWS accounts enforce account-level S3 Block Public Access. If that control is enabled, Terraform may fail when applying the public bucket policy. That is a good real-world guardrail; for demo purposes, use a sandbox account where you understand and control the account-level setting.

