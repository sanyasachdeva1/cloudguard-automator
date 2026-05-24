from __future__ import annotations

import argparse

from cloudguard_automator.remediation import build_plan, render_plan_json, render_plan_markdown
from cloudguard_automator.report import render_json, render_markdown, write_report
from cloudguard_automator.scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="Audit AWS environments for cloud security posture risks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run AWS security posture checks.")
    scan.add_argument("--profile", help="AWS profile name to use.")
    scan.add_argument("--regions", nargs="+", default=["us-east-1"], help="AWS regions to scan.")
    scan.add_argument("--demo", action="store_true", help="Use built-in demo findings.")
    scan.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Report format.")
    scan.add_argument("--output", help="Path to write the report.")

    remediate = subparsers.add_parser("remediate", help="Generate a dry-run remediation plan from findings.")
    remediate.add_argument("--profile", help="AWS profile name to use.")
    remediate.add_argument("--regions", nargs="+", default=["us-east-1"], help="AWS regions to scan.")
    remediate.add_argument("--demo", action="store_true", help="Use built-in demo findings.")
    remediate.add_argument("--dry-run", action="store_true", required=True, help="Generate remediation steps without applying changes.")
    remediate.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Plan format.")
    remediate.add_argument("--output", help="Path to write the remediation plan.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        findings = run_scan(profile=args.profile, regions=args.regions, demo=args.demo)
        content = render_json(findings) if args.format == "json" else render_markdown(findings)
        write_report(content, args.output)
    elif args.command == "remediate":
        findings = run_scan(profile=args.profile, regions=args.regions, demo=args.demo)
        steps = build_plan(findings)
        content = render_plan_json(steps) if args.format == "json" else render_plan_markdown(steps)
        write_report(content, args.output)
