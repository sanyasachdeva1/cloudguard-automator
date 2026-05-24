from __future__ import annotations

import argparse

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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        findings = run_scan(profile=args.profile, regions=args.regions, demo=args.demo)
        content = render_json(findings) if args.format == "json" else render_markdown(findings)
        write_report(content, args.output)

