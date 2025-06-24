"""AWS GuardDuty MCP Server for secure GuardDuty API access."""

__version__ = "1.0.0"
__author__ = "GuardDuty MCP Server"

from .guardduty_client import GuardDutyClient
from .mcp_server import GuardDutyMCPServer

__all__ = ["GuardDutyClient", "GuardDutyMCPServer"]