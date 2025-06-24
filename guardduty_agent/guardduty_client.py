"""AWS GuardDuty client using boto3."""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


class GuardDutyClient:
    """AWS GuardDuty client wrapper using boto3."""

    def __init__(self, region_name: Optional[str] = None) -> None:
        """Initialize GuardDuty client.
        
        Args:
            region_name: AWS region name. If None, uses default from environment.
        """
        try:
            self.client = boto3.client("guardduty", region_name=region_name)
            self.region = region_name or boto3.Session().region_name
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure your credentials.")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize GuardDuty client: {e}")
            raise

    async def get_findings(
        self,
        detector_id: str,
        finding_criteria: Optional[Dict[str, Any]] = None,
        max_results: int = 50,
    ) -> Dict[str, Any]:
        """Retrieve GuardDuty findings with optional filters.
        
        Args:
            detector_id: GuardDuty detector ID
            finding_criteria: Optional filtering criteria
            max_results: Maximum number of findings to return
            
        Returns:
            Dictionary containing findings and metadata
        """
        try:
            # Convert async call to sync for boto3
            loop = asyncio.get_event_loop()
            
            # List findings with criteria
            list_params = {
                "DetectorId": detector_id,
                "MaxResults": max_results,
            }
            
            if finding_criteria:
                list_params["FindingCriteria"] = self._build_finding_criteria(
                    finding_criteria
                )
            
            list_response = await loop.run_in_executor(
                None, lambda: self.client.list_findings(**list_params)
            )
            
            if not list_response.get("FindingIds"):
                return {"findings": [], "count": 0}
            
            # Get detailed findings
            get_response = await loop.run_in_executor(
                None,
                lambda: self.client.get_findings(
                    DetectorId=detector_id, FindingIds=list_response["FindingIds"]
                ),
            )
            
            findings = get_response.get("Findings", [])
            
            return {
                "findings": findings,
                "count": len(findings),
                "has_more": len(list_response["FindingIds"]) == max_results,
                "detector_id": detector_id,
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(f"AWS GuardDuty error [{error_code}]: {error_message}")
            raise RuntimeError(f"Failed to get findings: {error_message}")
        except Exception as e:
            logger.error(f"Unexpected error getting findings: {e}")
            raise

    async def get_malware_scans(
        self,
        detector_id: str,
        scan_id: Optional[str] = None,
        max_results: int = 50,
    ) -> Dict[str, Any]:
        """Retrieve malware scan results.
        
        Args:
            detector_id: GuardDuty detector ID
            scan_id: Optional specific scan ID
            max_results: Maximum number of scans to return
            
        Returns:
            Dictionary containing scan results
        """
        try:
            loop = asyncio.get_event_loop()
            
            params = {
                "DetectorId": detector_id,
                "MaxResults": max_results,
            }
            
            if scan_id:
                params["ScanIds"] = [scan_id]
            
            response = await loop.run_in_executor(
                None, lambda: self.client.describe_malware_scans(**params)
            )
            
            scans = response.get("Scans", [])
            
            return {
                "scans": scans,
                "count": len(scans),
                "detector_id": detector_id,
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(f"AWS GuardDuty error [{error_code}]: {error_message}")
            raise RuntimeError(f"Failed to get malware scans: {error_message}")
        except Exception as e:
            logger.error(f"Unexpected error getting malware scans: {e}")
            raise

    async def start_malware_scan(
        self, detector_id: str, resource_arn: str
    ) -> Dict[str, Any]:
        """Initiate malware scan on EBS volumes.
        
        Args:
            detector_id: GuardDuty detector ID
            resource_arn: ARN of the resource to scan
            
        Returns:
            Dictionary with scan ID and status
        """
        try:
            loop = asyncio.get_event_loop()
            
            response = await loop.run_in_executor(
                None,
                lambda: self.client.start_malware_scan(
                    DetectorId=detector_id, ResourceArn=resource_arn
                ),
            )
            
            return {
                "scan_id": response.get("ScanId"),
                "message": "Malware scan initiated successfully",
                "detector_id": detector_id,
                "resource_arn": resource_arn,
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(f"AWS GuardDuty error [{error_code}]: {error_message}")
            raise RuntimeError(f"Failed to start malware scan: {error_message}")
        except Exception as e:
            logger.error(f"Unexpected error starting malware scan: {e}")
            raise

    async def get_detector_status(self, detector_id: str) -> Dict[str, Any]:
        """Get GuardDuty detector configuration and status.
        
        Args:
            detector_id: GuardDuty detector ID
            
        Returns:
            Dictionary containing detector information
        """
        try:
            loop = asyncio.get_event_loop()
            
            response = await loop.run_in_executor(
                None, lambda: self.client.get_detector(DetectorId=detector_id)
            )
            
            return {
                "detector_id": detector_id,
                "status": response.get("Status"),
                "service_role": response.get("ServiceRole"),
                "finding_publishing_frequency": response.get("FindingPublishingFrequency"),
                "malware_protection": response.get("MalwareProtection"),
                "data_sources": response.get("DataSources"),
                "features": response.get("Features"),
                "created_at": response.get("CreatedAt"),
                "updated_at": response.get("UpdatedAt"),
                "tags": response.get("Tags", {}),
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(f"AWS GuardDuty error [{error_code}]: {error_message}")
            raise RuntimeError(f"Failed to get detector status: {error_message}")
        except Exception as e:
            logger.error(f"Unexpected error getting detector status: {e}")
            raise

    async def generate_threat_report(
        self,
        detector_id: str,
        time_range: Optional[Dict[str, str]] = None,
        format: str = "summary",
    ) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence report.
        
        Args:
            detector_id: GuardDuty detector ID
            time_range: Optional time range with 'start' and 'end' keys
            format: Report format ('json' or 'summary')
            
        Returns:
            Dictionary containing threat report
        """
        try:
            criteria = {}
            
            if time_range and time_range.get("start") and time_range.get("end"):
                start_time = datetime.fromisoformat(
                    time_range["start"].replace("Z", "+00:00")
                )
                end_time = datetime.fromisoformat(
                    time_range["end"].replace("Z", "+00:00")
                )
                
                criteria["updatedAt"] = {
                    "GreaterThanOrEqual": int(start_time.timestamp() * 1000),
                    "LessThanOrEqual": int(end_time.timestamp() * 1000),
                }
            
            # Get findings for the report
            findings_data = await self.get_findings(
                detector_id=detector_id,
                finding_criteria=criteria,
                max_results=100,
            )
            
            findings = findings_data["findings"]
            
            if format == "json":
                return self._generate_detailed_report(findings)
            else:
                return self._generate_summary_report(findings)
                
        except Exception as e:
            logger.error(f"Failed to generate threat report: {e}")
            raise

    async def list_detectors(self) -> Dict[str, Any]:
        """List all GuardDuty detectors in the region.
        
        Returns:
            Dictionary containing detector IDs
        """
        try:
            loop = asyncio.get_event_loop()
            
            response = await loop.run_in_executor(
                None, lambda: self.client.list_detectors()
            )
            
            detector_ids = response.get("DetectorIds", [])
            
            return {"detector_ids": detector_ids, "count": len(detector_ids)}
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(f"AWS GuardDuty error [{error_code}]: {error_message}")
            raise RuntimeError(f"Failed to list detectors: {error_message}")
        except Exception as e:
            logger.error(f"Unexpected error listing detectors: {e}")
            raise

    def _build_finding_criteria(self, criteria: Dict[str, Any]) -> Dict[str, Any]:
        """Build GuardDuty finding criteria from input parameters.
        
        Args:
            criteria: Input criteria dictionary
            
        Returns:
            Formatted finding criteria for GuardDuty API
        """
        finding_criterion = {}
        
        if criteria.get("severity"):
            finding_criterion["severity"] = {"Eq": criteria["severity"]}
        
        if criteria.get("type"):
            finding_criterion["type"] = {"Eq": criteria["type"]}
        
        if criteria.get("updated_at"):
            finding_criterion["updatedAt"] = {}
            
            if criteria["updated_at"].get("gte"):
                finding_criterion["updatedAt"]["GreaterThanOrEqual"] = criteria[
                    "updated_at"
                ]["gte"]
            
            if criteria["updated_at"].get("lte"):
                finding_criterion["updatedAt"]["LessThanOrEqual"] = criteria[
                    "updated_at"
                ]["lte"]
        
        return finding_criterion

    def _generate_detailed_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed JSON report from findings.
        
        Args:
            findings: List of GuardDuty findings
            
        Returns:
            Detailed report dictionary
        """
        severity_count = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        type_count: Dict[str, int] = {}
        resource_count: Dict[str, int] = {}
        
        for finding in findings:
            severity = finding.get("Severity", "UNKNOWN")
            if severity in severity_count:
                severity_count[severity] += 1
            
            finding_type = finding.get("Type", "Unknown")
            type_count[finding_type] = type_count.get(finding_type, 0) + 1
            
            resource = finding.get("Resource", {})
            resource_type = resource.get("ResourceType", "Unknown")
            resource_count[resource_type] = resource_count.get(resource_type, 0) + 1
        
        return {
            "summary": {
                "total_findings": len(findings),
                "severity_breakdown": severity_count,
                "type_breakdown": type_count,
                "resource_breakdown": resource_count,
                "generated_at": datetime.utcnow().isoformat(),
            },
            "findings": [
                {
                    "id": finding.get("Id"),
                    "type": finding.get("Type"),
                    "severity": finding.get("Severity"),
                    "title": finding.get("Title"),
                    "description": finding.get("Description"),
                    "resource": finding.get("Resource"),
                    "service": finding.get("Service"),
                    "created_at": finding.get("CreatedAt"),
                    "updated_at": finding.get("UpdatedAt"),
                }
                for finding in findings
            ],
        }

    def _generate_summary_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary report from findings.
        
        Args:
            findings: List of GuardDuty findings
            
        Returns:
            Summary report dictionary
        """
        severity_count = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        type_count: Dict[str, int] = {}
        
        for finding in findings:
            severity = finding.get("Severity", "UNKNOWN")
            if severity in severity_count:
                severity_count[severity] += 1
            
            finding_type = finding.get("Type", "Unknown")
            type_count[finding_type] = type_count.get(finding_type, 0) + 1
        
        critical_findings = [
            f for f in findings if f.get("Severity") == "HIGH"
        ][:5]
        
        summary_lines = [
            "# GuardDuty Threat Intelligence Report",
            f"Generated: {datetime.utcnow().isoformat()}",
            "",
            "## Summary",
            f"- Total Findings: {len(findings)}",
            f"- High Severity: {severity_count['HIGH']}",
            f"- Medium Severity: {severity_count['MEDIUM']}",
            f"- Low Severity: {severity_count['LOW']}",
            "",
            "## Top Threat Types",
        ]
        
        # Add top threat types
        sorted_types = sorted(type_count.items(), key=lambda x: x[1], reverse=True)[:5]
        for threat_type, count in sorted_types:
            summary_lines.append(f"- {threat_type}: {count} findings")
        
        # Add critical findings if any
        if critical_findings:
            summary_lines.extend(["", "## Critical Findings (Top 5)"])
            for i, finding in enumerate(critical_findings, 1):
                resource_type = finding.get("Resource", {}).get("ResourceType", "Unknown")
                summary_lines.extend([
                    f"{i}. {finding.get('Title', 'Unknown')} ({finding.get('Type', 'Unknown')})",
                    f"   Resource: {resource_type}",
                    f"   Updated: {finding.get('UpdatedAt', 'Unknown')}",
                    "",
                ])
        
        return {"summary": "\n".join(summary_lines)}