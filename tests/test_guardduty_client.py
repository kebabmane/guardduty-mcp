"""Tests for GuardDuty client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from guardduty_agent.guardduty_client import GuardDutyClient


@pytest.fixture
def mock_boto3_client():
    """Mock boto3 GuardDuty client."""
    with patch("guardduty_agent.guardduty_client.boto3") as mock_boto3:
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        mock_boto3.Session.return_value.region_name = "us-east-1"
        yield mock_client


@pytest.fixture
def guardduty_client(mock_boto3_client):
    """Create GuardDuty client instance."""
    return GuardDutyClient("us-east-1")


class TestGuardDutyClient:
    """Test cases for GuardDutyClient."""

    def test_init(self, mock_boto3_client):
        """Test client initialization."""
        client = GuardDutyClient("us-west-2")
        assert client.region == "us-west-2"

    def test_init_default_region(self, mock_boto3_client):
        """Test client initialization with default region."""
        client = GuardDutyClient()
        assert client.region == "us-east-1"

    @pytest.mark.asyncio
    async def test_get_findings_empty(self, guardduty_client, mock_boto3_client):
        """Test getting findings when none exist."""
        mock_boto3_client.list_findings.return_value = {"FindingIds": []}
        
        result = await guardduty_client.get_findings("detector-123")
        
        assert result == {"findings": [], "count": 0}
        mock_boto3_client.list_findings.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_findings_success(self, guardduty_client, mock_boto3_client):
        """Test successful finding retrieval."""
        # Mock list_findings response
        mock_boto3_client.list_findings.return_value = {
            "FindingIds": ["finding-1", "finding-2"]
        }
        
        # Mock get_findings response
        mock_boto3_client.get_findings.return_value = {
            "Findings": [
                {
                    "Id": "finding-1",
                    "Type": "Trojan:EC2/DNSDataExfiltration",
                    "Severity": "HIGH",
                    "Title": "Test Finding 1"
                },
                {
                    "Id": "finding-2",
                    "Type": "Backdoor:EC2/C&CActivity.B",
                    "Severity": "MEDIUM",
                    "Title": "Test Finding 2"
                }
            ]
        }
        
        result = await guardduty_client.get_findings("detector-123")
        
        assert result["count"] == 2
        assert len(result["findings"]) == 2
        assert result["findings"][0]["Id"] == "finding-1"
        assert result["detector_id"] == "detector-123"

    @pytest.mark.asyncio
    async def test_get_findings_with_criteria(self, guardduty_client, mock_boto3_client):
        """Test getting findings with filtering criteria."""
        mock_boto3_client.list_findings.return_value = {"FindingIds": ["finding-1"]}
        mock_boto3_client.get_findings.return_value = {
            "Findings": [{"Id": "finding-1", "Severity": "HIGH"}]
        }
        
        criteria = {"severity": ["HIGH"], "type": ["Trojan:EC2/DNSDataExfiltration"]}
        
        await guardduty_client.get_findings("detector-123", criteria)
        
        # Verify that finding criteria was built and passed
        call_args = mock_boto3_client.list_findings.call_args
        assert "FindingCriteria" in call_args[1]

    @pytest.mark.asyncio
    async def test_get_malware_scans(self, guardduty_client, mock_boto3_client):
        """Test getting malware scans."""
        mock_boto3_client.describe_malware_scans.return_value = {
            "Scans": [
                {
                    "ScanId": "scan-1",
                    "ScanStatus": "COMPLETED",
                    "ScanResultDetails": {"ThreatDetectedDetails": {"ThreatName": "Test"}}
                }
            ]
        }
        
        result = await guardduty_client.get_malware_scans("detector-123")
        
        assert result["count"] == 1
        assert result["scans"][0]["ScanId"] == "scan-1"

    @pytest.mark.asyncio
    async def test_start_malware_scan(self, guardduty_client, mock_boto3_client):
        """Test starting malware scan."""
        mock_boto3_client.start_malware_scan.return_value = {"ScanId": "scan-new"}
        
        result = await guardduty_client.start_malware_scan(
            "detector-123", "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
        )
        
        assert result["scan_id"] == "scan-new"
        assert "successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_get_detector_status(self, guardduty_client, mock_boto3_client):
        """Test getting detector status."""
        mock_boto3_client.get_detector.return_value = {
            "Status": "ENABLED",
            "ServiceRole": "arn:aws:iam::123456789012:role/aws-guardduty-role",
            "FindingPublishingFrequency": "SIX_HOURS",
            "CreatedAt": datetime.now(),
            "UpdatedAt": datetime.now()
        }
        
        result = await guardduty_client.get_detector_status("detector-123")
        
        assert result["detector_id"] == "detector-123"
        assert result["status"] == "ENABLED"

    @pytest.mark.asyncio
    async def test_list_detectors(self, guardduty_client, mock_boto3_client):
        """Test listing detectors."""
        mock_boto3_client.list_detectors.return_value = {
            "DetectorIds": ["detector-1", "detector-2"]
        }
        
        result = await guardduty_client.list_detectors()
        
        assert result["count"] == 2
        assert "detector-1" in result["detector_ids"]

    def test_build_finding_criteria(self, guardduty_client):
        """Test building finding criteria."""
        criteria = {
            "severity": ["HIGH", "MEDIUM"],
            "type": ["Trojan:EC2/DNSDataExfiltration"],
            "updated_at": {"gte": 1640995200000, "lte": 1641081600000}
        }
        
        result = guardduty_client._build_finding_criteria(criteria)
        
        assert result["severity"]["Eq"] == ["HIGH", "MEDIUM"]
        assert result["type"]["Eq"] == ["Trojan:EC2/DNSDataExfiltration"]
        assert result["updatedAt"]["GreaterThanOrEqual"] == 1640995200000

    def test_generate_summary_report(self, guardduty_client):
        """Test generating summary report."""
        findings = [
            {
                "Id": "1",
                "Type": "Trojan:EC2/DNSDataExfiltration",
                "Severity": "HIGH",
                "Title": "Test Finding 1",
                "Resource": {"ResourceType": "Instance"},
                "UpdatedAt": "2024-01-01T00:00:00Z"
            },
            {
                "Id": "2",
                "Type": "Backdoor:EC2/C&CActivity.B",
                "Severity": "MEDIUM",
                "Title": "Test Finding 2",
                "Resource": {"ResourceType": "Instance"},
                "UpdatedAt": "2024-01-01T01:00:00Z"
            }
        ]
        
        result = guardduty_client._generate_summary_report(findings)
        
        assert "Total Findings: 2" in result["summary"]
        assert "High Severity: 1" in result["summary"]
        assert "Medium Severity: 1" in result["summary"]
        assert "Trojan:EC2/DNSDataExfiltration: 1" in result["summary"]

    def test_generate_detailed_report(self, guardduty_client):
        """Test generating detailed report."""
        findings = [
            {
                "Id": "1",
                "Type": "Trojan:EC2/DNSDataExfiltration",
                "Severity": "HIGH",
                "Title": "Test Finding",
                "Description": "Test description",
                "Resource": {"ResourceType": "Instance"},
                "Service": {},
                "CreatedAt": "2024-01-01T00:00:00Z",
                "UpdatedAt": "2024-01-01T00:00:00Z"
            }
        ]
        
        result = guardduty_client._generate_detailed_report(findings)
        
        assert result["summary"]["total_findings"] == 1
        assert result["summary"]["severity_breakdown"]["HIGH"] == 1
        assert len(result["findings"]) == 1
        assert result["findings"][0]["id"] == "1"

    @pytest.mark.asyncio
    async def test_client_error_handling(self, guardduty_client, mock_boto3_client):
        """Test AWS client error handling."""
        from botocore.exceptions import ClientError
        
        error_response = {
            "Error": {
                "Code": "InvalidDetectorId",
                "Message": "The detector ID is invalid"
            }
        }
        
        mock_boto3_client.list_findings.side_effect = ClientError(
            error_response, "ListFindings"
        )
        
        with pytest.raises(RuntimeError, match="Failed to get findings"):
            await guardduty_client.get_findings("invalid-detector")