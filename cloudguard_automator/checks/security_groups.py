from __future__ import annotations

from cloudguard_automator.models import Finding, Severity


RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


def scan(session, region: str) -> list[Finding]:
    client = session.client("ec2")
    findings: list[Finding] = []

    for group in client.describe_security_groups().get("SecurityGroups", []):
        group_id = group["GroupId"]
        for rule in group.get("IpPermissions", []):
            findings.extend(_evaluate_ingress_rule(group_id, rule, region))

    return findings


def _evaluate_ingress_rule(group_id: str, rule: dict, region: str) -> list[Finding]:
    findings: list[Finding] = []
    cidrs = [item.get("CidrIp") for item in rule.get("IpRanges", [])]
    cidrs.extend(item.get("CidrIpv6") for item in rule.get("Ipv6Ranges", []))
    public_cidrs = {cidr for cidr in cidrs if cidr in {"0.0.0.0/0", "::/0"}}

    if not public_cidrs:
        return findings

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port is None or to_port is None:
        findings.append(_finding(group_id, region, "all traffic", Severity.CRITICAL))
        return findings

    for port, label in RISKY_PORTS.items():
        if from_port <= port <= to_port:
            findings.append(_finding(group_id, region, f"{label} ({port})", Severity.CRITICAL))

    if from_port == 0 and to_port == 65535:
        findings.append(_finding(group_id, region, "all TCP ports", Severity.CRITICAL))

    return findings


def _finding(group_id: str, region: str, exposure: str, severity: Severity) -> Finding:
    return Finding(
        check_id="EC2_SECURITY_GROUP_PUBLIC_INGRESS",
        title=f"Security group exposes {exposure} to the internet",
        severity=severity,
        resource=group_id,
        region=region,
        service="ec2",
        description=f"The security group allows inbound {exposure} from 0.0.0.0/0 or ::/0.",
        remediation="Restrict inbound access to trusted CIDR ranges or replace direct access with private connectivity.",
    )

