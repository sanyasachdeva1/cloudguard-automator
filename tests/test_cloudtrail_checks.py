from cloudguard_automator.checks import cloudtrail


class FakeCloudTrailClient:
    def __init__(self, trails):
        self.trails = trails

    def describe_trails(self, includeShadowTrails):
        return {"trailList": self.trails}

    def get_trail_status(self, Name):
        return {"IsLogging": False}

    def get_event_selectors(self, TrailName):
        return {"EventSelectors": [{"IncludeManagementEvents": False}]}


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "cloudtrail"
        return self._client


def test_scan_detects_missing_cloudtrail():
    findings = cloudtrail.scan(FakeSession(FakeCloudTrailClient([])), "us-east-1")

    assert findings[0].check_id == "CLOUDTRAIL_NOT_CONFIGURED"


def test_scan_detects_cloudtrail_baseline_gaps():
    client = FakeCloudTrailClient(
        [
            {
                "Name": "org-trail",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": False,
            }
        ]
    )

    findings = cloudtrail.scan(FakeSession(client), "us-east-1")
    check_ids = {finding.check_id for finding in findings}

    assert "CLOUDTRAIL_NOT_LOGGING" in check_ids
    assert "CLOUDTRAIL_NOT_MULTI_REGION" in check_ids
    assert "CLOUDTRAIL_LOG_VALIDATION_DISABLED" in check_ids
    assert "CLOUDTRAIL_KMS_ENCRYPTION_DISABLED" in check_ids
    assert "CLOUDTRAIL_MANAGEMENT_EVENTS_DISABLED" in check_ids


def test_advanced_management_event_selector_counts_as_enabled():
    class AdvancedSelectorClient(FakeCloudTrailClient):
        def get_event_selectors(self, TrailName):
            return {
                "AdvancedEventSelectors": [
                    {
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]},
                        ]
                    }
                ]
            }

    assert cloudtrail._management_events_enabled(AdvancedSelectorClient([]), "org-trail")

