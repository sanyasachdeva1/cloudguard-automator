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
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
ALL_PORTS = (0, 65535)


def scan(session, region: str) -> list[Finding]:
    client = session.client("ec2")
    findings: list[Finding] = []

    for group in client.describe_security_groups().get("SecurityGroups", []):
        group_id = group["GroupId"]
        group_name = group.get("GroupName", group_id)
        for rule in group.get("IpPermissions", []):
            findings.extend(_evaluate_ingress_rule(group_id, group_name, rule, region))

    return findings


def _evaluate_ingress_rule(group_id: str, group_name: str, rule: dict, region: str) -> list[Finding]:
    findings: list[Finding] = []
    cidrs = [item.get("CidrIp") for item in rule.get("IpRanges", [])]
    cidrs.extend(item.get("CidrIpv6") for item in rule.get("Ipv6Ranges", []))
    public_cidrs = sorted(cidr for cidr in cidrs if cidr in PUBLIC_CIDRS)

    if not public_cidrs:
        return findings

    protocol = rule.get("IpProtocol", "-1")
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if protocol == "-1" or from_port is None or to_port is None:
        findings.append(_finding(group_id, group_name, region, "all traffic", Severity.CRITICAL, public_cidrs))
        return findings

    if from_port <= ALL_PORTS[0] and to_port >= ALL_PORTS[1]:
        findings.append(_finding(group_id, group_name, region, "all TCP ports", Severity.CRITICAL, public_cidrs))
        return findings

    for port, label in RISKY_PORTS.items():
        if from_port <= port <= to_port:
            findings.append(_finding(group_id, group_name, region, f"{label} ({port})", Severity.CRITICAL, public_cidrs))

    if not findings and _is_broad_port_range(from_port, to_port):
        findings.append(
            _finding(
                group_id,
                group_name,
                region,
                f"broad port range {from_port}-{to_port}",
                Severity.MEDIUM,
                public_cidrs,
            )
        )

    return findings


def _is_broad_port_range(from_port: int, to_port: int) -> bool:
    return to_port - from_port >= 100


def _finding(group_id: str, group_name: str, region: str, exposure: str, severity: Severity, public_cidrs: list[str]) -> Finding:
    return Finding(
        check_id="EC2_SECURITY_GROUP_PUBLIC_INGRESS",
        title=f'Security group "{group_name}" exposes {exposure} to the internet',
        severity=severity,
        resource=group_id,
        region=region,
        service="ec2",
        description=f"The security group allows inbound {exposure} from {', '.join(public_cidrs)}.",
        remediation="Restrict inbound access to trusted CIDR ranges or replace direct access with private connectivity.",
    )
