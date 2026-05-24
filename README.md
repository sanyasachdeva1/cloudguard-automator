# CloudGuard Automator

CloudGuard Automator is a cloud security automation toolkit for auditing AWS environments for common IAM, S3, CloudTrail, and network exposure risks.

The goal is to build a practical, portfolio-grade CSPM-style tool: scan an AWS account, identify risky misconfigurations, assign severity, and generate remediation-ready reports.

## Why This Project Matters

Cloud environments fail in predictable ways: public storage, over-permissive IAM, missing logging, and exposed network services. This toolkit turns those risks into repeatable checks that can be run from a terminal, CI job, or security workflow.

## Current Scope

- IAM baseline checks, including MFA, password policy, stale access keys, direct admin attachment, and wildcard policies
- S3 bucket exposure and hardening checks, including public ACLs, public policies, encryption, versioning, logging, and Block Public Access
- CloudTrail logging baseline checks, including active logging, multi-region coverage, log validation, KMS encryption, and management events
- EC2 security group exposure checks, including public admin ports, public database ports, all-traffic rules, IPv6 exposure, and broad port ranges
- Severity and risk scoring
- JSON and Markdown reports
- Demo mode for portfolio screenshots without needing live AWS credentials

## Planned Roadmap

| Phase | Focus | Outcome |
| --- | --- | --- |
| 1 | CLI, finding model, demo report | A usable portfolio MVP |
| 2 | S3 scanner | Detect public ACLs, public policies, missing encryption, missing versioning, missing access logging |
| 3 | IAM scanner | Detect missing MFA, stale keys, direct admin attachment, and wildcard policies |
| 4 | CloudTrail scanner | Validate multi-region logging, log validation, KMS encryption, and management events |
| 5 | Security group scanner | Detect internet-exposed admin/database ports, all-traffic rules, IPv6 exposure, and broad ranges |
| 6 | Remediation mode | Dry-run and safe fixes for selected issues |
| 7 | Vulnerable AWS lab | Terraform lab for repeatable demos |

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run demo mode:

```bash
cloudguard scan --demo --format markdown --output reports/demo_report.md
```

Run against AWS credentials configured in your environment:

```bash
cloudguard scan --profile default --regions us-east-1 ap-south-1 --format json
```

## Example Finding

```text
HIGH: S3 bucket "company-backups" does not block public access.
Risk: Publicly exposed storage can leak sensitive files or backups.
Remediation: Enable S3 Block Public Access at the bucket or account level.
```

## Safety

This project starts as a read-only scanner. Remediation features will be added behind explicit dry-run/apply flags so changes are deliberate and auditable.
