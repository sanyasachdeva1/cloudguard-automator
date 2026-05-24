from cloudguard_automator.checks import security_groups


class FakeEc2Client:
    def __init__(self, groups):
        self.groups = groups

    def describe_security_groups(self):
        return {"SecurityGroups": self.groups}


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "ec2"
        return self._client


def test_scan_detects_public_admin_and_database_ports():
    groups = [
        {
            "GroupId": "sg-admin",
            "GroupName": "admin-access",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        }
    ]

    findings = security_groups.scan(FakeSession(FakeEc2Client(groups)), "us-east-1")
    titles = {finding.title for finding in findings}

    assert 'Security group "admin-access" exposes SSH (22) to the internet' in titles
    assert 'Security group "admin-access" exposes PostgreSQL (5432) to the internet' in titles
    assert all(finding.severity.value == "critical" for finding in findings)


def test_scan_reports_all_traffic_once():
    groups = [
        {
            "GroupId": "sg-all",
            "GroupName": "all-open",
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        }
    ]

    findings = security_groups.scan(FakeSession(FakeEc2Client(groups)), "us-east-1")

    assert len(findings) == 1
    assert findings[0].title == 'Security group "all-open" exposes all traffic to the internet'


def test_scan_detects_broad_public_port_range_without_sensitive_ports():
    groups = [
        {
            "GroupId": "sg-broad",
            "GroupName": "wide-app-range",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8000,
                    "ToPort": 8200,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        }
    ]

    findings = security_groups.scan(FakeSession(FakeEc2Client(groups)), "us-east-1")

    assert len(findings) == 1
    assert findings[0].check_id == "EC2_SECURITY_GROUP_PUBLIC_INGRESS"
    assert findings[0].severity.value == "medium"


def test_scan_ignores_private_ranges():
    groups = [
        {
            "GroupId": "sg-private",
            "GroupName": "private-admin",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                }
            ],
        }
    ]

    findings = security_groups.scan(FakeSession(FakeEc2Client(groups)), "us-east-1")

    assert findings == []

