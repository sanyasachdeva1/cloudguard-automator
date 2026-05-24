from datetime import UTC, datetime, timedelta

from cloudguard_automator.checks import iam


class ClientError(Exception):
    pass


class FakeIamClient:
    def __init__(self):
        now = datetime.now(UTC)
        self.users = [{"UserName": "backup-admin"}]
        self.access_keys = [
            {
                "AccessKeyId": "AKIAOLDUNUSED",
                "Status": "Active",
                "CreateDate": now - timedelta(days=120),
            },
            {
                "AccessKeyId": "AKIASTALEUSED",
                "Status": "Active",
                "CreateDate": now - timedelta(days=200),
            },
        ]

    def list_users(self):
        return {"Users": self.users}

    def get_login_profile(self, UserName):
        return {"LoginProfile": {"UserName": UserName}}

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": self.access_keys}

    def get_access_key_last_used(self, AccessKeyId):
        if AccessKeyId == "AKIASTALEUSED":
            return {"AccessKeyLastUsed": {"LastUsedDate": datetime.now(UTC) - timedelta(days=121)}}
        return {"AccessKeyLastUsed": {}}

    def list_attached_user_policies(self, UserName):
        return {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                }
            ]
        }

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        return {
            "PolicyVersion": {
                "Document": {
                    "Statement": {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                }
            }
        }

    def list_user_policies(self, UserName):
        return {"PolicyNames": ["inline-admin"]}

    def get_user_policy(self, UserName, PolicyName):
        return {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["*"],
                    "Resource": ["*"],
                }
            }
        }

    def get_account_password_policy(self):
        return {"PasswordPolicy": {"MinimumPasswordLength": 8, "RequireSymbols": False, "RequireNumbers": True}}


class FakeSession:
    def client(self, service_name):
        assert service_name == "iam"
        return FakeIamClient()


def test_scan_detects_iam_identity_risks():
    findings = iam.scan(FakeSession())
    check_ids = {finding.check_id for finding in findings}

    assert "IAM_USER_MFA_DISABLED" in check_ids
    assert "IAM_UNUSED_ACCESS_KEY" in check_ids
    assert "IAM_STALE_ACCESS_KEY" in check_ids
    assert "IAM_USER_DIRECT_ADMIN_POLICY" in check_ids
    assert "IAM_POLICY_FULL_ADMIN_WILDCARD" in check_ids
    assert "IAM_PASSWORD_POLICY_WEAK" in check_ids


def test_policy_wildcard_detection_handles_lists_and_strings():
    assert iam._policy_has_full_admin_access(
        {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    )
    assert iam._policy_has_full_admin_access(
        {"Statement": {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": ["*"]}}
    )
    assert not iam._policy_has_full_admin_access(
        {"Statement": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::example/*"]}}
    )

