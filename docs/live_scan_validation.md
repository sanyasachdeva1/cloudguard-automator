# Live Scan Validation

This document records how CloudGuard Automator should be validated against a sandbox AWS account before using it as a resume bullet or demo artifact.

## Validation Checklist

- Demo mode runs successfully.
- Unit tests pass locally and in GitHub Actions.
- Terraform vulnerable lab validates with `terraform validate`.
- A sandbox AWS scan runs with read-only credentials.
- Generated report contains expected IAM, S3, CloudTrail, and security group findings.
- Dry-run remediation plan generates commands or manual-review guidance.
- Terraform lab is destroyed after testing.

## Suggested Sandbox Flow

```bash
cd terraform/lab
terraform init
terraform apply
```

From the repository root:

```bash
cloudguard scan --profile default --regions us-east-1 --format html --output reports/lab_scan.html
cloudguard remediate --profile default --regions us-east-1 --dry-run --format markdown --output reports/lab_remediation.md
```

Destroy the lab:

```bash
cd terraform/lab
terraform destroy
```

## Validation Record

| Field | Value |
| --- | --- |
| Date tested | Not yet recorded |
| AWS account type | Sandbox |
| Region | `us-east-1` |
| Credentials used | Read-only audit role or profile |
| Scanner command | `cloudguard scan --profile default --regions us-east-1 --format html --output reports/lab_scan.html` |
| Result summary | Pending live validation |
| Lab destroyed | Pending |

## Known Limitations

- The toolkit is intentionally focused on IAM, S3, CloudTrail, and EC2 security group checks.
- It does not replace mature CSPM tools such as Prowler, ScoutSuite, AWS Security Hub, or commercial CNAPP platforms.
- Control mappings are lightweight guidance, not formal compliance certification.

