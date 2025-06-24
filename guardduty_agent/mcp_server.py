"""MCP Server implementation for GuardDuty tools."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

from .guardduty_client import GuardDutyClient

logger = logging.getLogger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""
    
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class GuardDutyMCPServer:
    """MCP Server for GuardDuty security operations."""

    def __init__(self) -> None:
        self.server = Server("guardduty-agent")
        self.guardduty_client = GuardDutyClient()
        self._setup_handlers()
        
        # Disable logging when used as MCP server to avoid stdout interference
        logger.setLevel(logging.CRITICAL)

    def _setup_handlers(self) -> None:
        """Set up MCP request handlers."""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available GuardDuty tools."""
            return [
                Tool(
                    name="get_findings",
                    description="Retrieve GuardDuty findings with optional filters",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detector_id": {
                                "type": "string",
                                "description": "GuardDuty detector ID",
                            },
                            "finding_criteria": {
                                "type": "object",
                                "description": "Filtering criteria for findings",
                                "properties": {
                                    "severity": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Filter by severity (LOW, MEDIUM, HIGH)",
                                    },
                                    "type": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                        "description": "Filter by finding type",
                                    },
                                    "updated_at": {
                                        "type": "object",
                                        "description": "Filter by last updated time range",
                                    },
                                },
                            },
                            "max_results": {
                                "type": "integer",
                                "description": "Maximum number of findings to return (default: 50)",
                            },
                        },
                        "required": ["detector_id"],
                    },
                ),
                Tool(
                    name="get_malware_scans",
                    description="Retrieve malware scan results",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detector_id": {
                                "type": "string",
                                "description": "GuardDuty detector ID",
                            },
                            "scan_id": {
                                "type": "string",
                                "description": "Specific scan ID to retrieve",
                            },
                            "max_results": {
                                "type": "integer",
                                "description": "Maximum number of scans to return",
                            },
                        },
                        "required": ["detector_id"],
                    },
                ),
                Tool(
                    name="start_malware_scan",
                    description="Initiate malware scan on EBS volumes",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detector_id": {
                                "type": "string",
                                "description": "GuardDuty detector ID",
                            },
                            "resource_arn": {
                                "type": "string",
                                "description": "ARN of the resource to scan",
                            },
                        },
                        "required": ["detector_id", "resource_arn"],
                    },
                ),
                Tool(
                    name="get_detector_status",
                    description="Get GuardDuty detector configuration and status",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detector_id": {
                                "type": "string",
                                "description": "GuardDuty detector ID",
                            }
                        },
                        "required": ["detector_id"],
                    },
                ),
                Tool(
                    name="generate_threat_report",
                    description="Generate comprehensive threat intelligence report",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detector_id": {
                                "type": "string",
                                "description": "GuardDuty detector ID",
                            },
                            "time_range": {
                                "type": "object",
                                "properties": {
                                    "start": {
                                        "type": "string",
                                        "description": "Start time (ISO 8601)",
                                    },
                                    "end": {
                                        "type": "string",
                                        "description": "End time (ISO 8601)",
                                    },
                                },
                                "description": "Time range for report generation",
                            },
                            "format": {
                                "type": "string",
                                "enum": ["json", "summary"],
                                "description": "Report format (default: summary)",
                            },
                        },
                        "required": ["detector_id"],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Handle tool calls."""
            try:
                if name == "get_findings":
                    result = await self._handle_get_findings(arguments)
                elif name == "get_malware_scans":
                    result = await self._handle_get_malware_scans(arguments)
                elif name == "start_malware_scan":
                    result = await self._handle_start_malware_scan(arguments)
                elif name == "get_detector_status":
                    result = await self._handle_get_detector_status(arguments)
                elif name == "generate_threat_report":
                    result = await self._handle_generate_threat_report(arguments)
                else:
                    raise ValueError(f"Unknown tool: {name}")

                return [TextContent(type="text", text=json.dumps(result, indent=2, cls=DateTimeEncoder))]

            except Exception as e:
                logger.error(f"Tool execution failed: {e}")
                return [
                    TextContent(
                        type="text", text=f"Error executing {name}: {str(e)}"
                    )
                ]

    async def _handle_get_findings(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_findings tool call."""
        return await self.guardduty_client.get_findings(
            detector_id=args["detector_id"],
            finding_criteria=args.get("finding_criteria", {}),
            max_results=args.get("max_results", 50),
        )

    async def _handle_get_malware_scans(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_malware_scans tool call."""
        return await self.guardduty_client.get_malware_scans(
            detector_id=args["detector_id"],
            scan_id=args.get("scan_id"),
            max_results=args.get("max_results", 50),
        )

    async def _handle_start_malware_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle start_malware_scan tool call."""
        return await self.guardduty_client.start_malware_scan(
            detector_id=args["detector_id"], resource_arn=args["resource_arn"]
        )

    async def _handle_get_detector_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_detector_status tool call."""
        return await self.guardduty_client.get_detector_status(
            detector_id=args["detector_id"]
        )

    async def _handle_generate_threat_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle generate_threat_report tool call."""
        return await self.guardduty_client.generate_threat_report(
            detector_id=args["detector_id"],
            time_range=args.get("time_range"),
            format=args.get("format", "summary"),
        )

    async def run_server(self) -> None:
        """Run the MCP server with stdio transport."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, write_stream, self.server.create_initialization_options()
            )


async def main() -> None:
    """Main entry point for the MCP server."""
    logging.basicConfig(level=logging.INFO)
    server = GuardDutyMCPServer()
    await server.run_server()


if __name__ == "__main__":
    asyncio.run(main())