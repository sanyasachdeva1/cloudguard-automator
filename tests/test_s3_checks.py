import json

from cloudguard_automator.checks import s3


class ClientError(Exception):
    pass


class FakeS3Client:
    def __init__(self, *, policy=None, acl=None, public_access_block=None, encryption=True, versioning=True, logging=True):
        self.policy = policy
        self.acl = acl or {"Grants": []}
        self.public_access_block = public_access_block or {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        self.encryption = encryption
        self.versioning = versioning
        self.logging = logging

    def list_buckets(self):
        return {"Buckets": [{"Name": "test-bucket"}]}

    def get_public_access_block(self, Bucket):
        return {"PublicAccessBlockConfiguration": self.public_access_block}

    def get_bucket_acl(self, Bucket):
        return self.acl

    def get_bucket_policy(self, Bucket):
        if self.policy is None:
            raise ClientError("NoSuchBucketPolicy")
        return {"Policy": json.dumps(self.policy)}

    def get_bucket_encryption(self, Bucket):
        if not self.encryption:
            raise ClientError("ServerSideEncryptionConfigurationNotFoundError")
        return {"ServerSideEncryptionConfiguration": {}}

    def get_bucket_versioning(self, Bucket):
        if not self.versioning:
            return {}
        return {"Status": "Enabled"}

    def get_bucket_logging(self, Bucket):
        if not self.logging:
            return {}
        return {"LoggingEnabled": {"TargetBucket": "logs-bucket", "TargetPrefix": "s3/"}}


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "s3"
        return self._client


def test_scan_detects_public_acl_and_policy():
    client = FakeS3Client(
        acl={
            "Grants": [
                {
                    "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ]
        },
        policy={
            "Statement": {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*",
            }
        },
    )

    findings = s3.scan(FakeSession(client))
    check_ids = {finding.check_id for finding in findings}

    assert "S3_PUBLIC_ACL" in check_ids
    assert "S3_PUBLIC_BUCKET_POLICY" in check_ids


def test_scan_detects_missing_s3_hardening():
    client = FakeS3Client(
        public_access_block={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        },
        encryption=False,
        versioning=False,
        logging=False,
    )

    findings = s3.scan(FakeSession(client))
    check_ids = {finding.check_id for finding in findings}

    assert "S3_PUBLIC_ACCESS_BLOCK_DISABLED" in check_ids
    assert "S3_DEFAULT_ENCRYPTION_MISSING" in check_ids
    assert "S3_VERSIONING_DISABLED" in check_ids
    assert "S3_ACCESS_LOGGING_DISABLED" in check_ids


def test_policy_with_restrictive_condition_is_not_public():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::test-bucket/*",
            "Condition": {"StringEquals": {"aws:PrincipalAccount": "123456789012"}},
        }
    }

    assert not s3._policy_allows_public_access(policy)
