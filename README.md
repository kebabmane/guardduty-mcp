# GuardDuty MCP Server

An MCP (Model Context Protocol) server for AWS GuardDuty integration, providing secure access to GuardDuty APIs for threat detection and security monitoring.

## Features

- **Real-time Threat Analysis**: Monitor and analyze GuardDuty findings with intelligent filtering
- **Malware Detection**: Automated malware scanning for EC2 instances and S3 buckets  
- **Threat Intelligence Reports**: Generate comprehensive security reports and summaries
- **MCP Integration**: Standard Model Context Protocol interface for AI assistants
- **Secure API Access**: Controlled access to GuardDuty APIs through MCP tools

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ MCP Client      │◄──►│ GuardDuty MCP    │◄──►│ AWS GuardDuty   │
│ (AI Assistant)  │    │ Server           │    │ API (boto3)     │
│                 │    │                  │    │                 │
│ - Tool Calls    │    │ - Tool Registry  │    │ - Findings      │
│ - Responses     │    │ - Request Router │    │ - Malware Scans │
│ - Analysis      │    │ - Response Format│    │ - Detectors     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.9+
- AWS account with GuardDuty enabled
- AWS credentials configured (IAM role, profile, or access keys)
- pip or poetry for package management

### Installation

```bash
git clone <repository>
cd guardduty-agent
pip install -e .
```

Or with poetry:
```bash
poetry install
```

### Configuration

1. Copy environment template:
```bash
cp .env.example .env
```

2. Configure your environment variables:
```bash
# AWS Configuration (choose one method)
AWS_REGION=us-east-1
AWS_PROFILE=default
# OR use access keys
# AWS_ACCESS_KEY_ID=your_access_key
# AWS_SECRET_ACCESS_KEY=your_secret_key

# GuardDuty Configuration  
GUARDDUTY_DETECTOR_ID=your_detector_id
```

### Usage

#### Run MCP Server
```bash
guardduty-agent server
```
Start the MCP server for GuardDuty integration.

#### List Detectors
```bash
guardduty-agent list-detectors
```
List all available GuardDuty detectors in your region.

## Available MCP Tools

The MCP server provides the following tools for GuardDuty operations:

### `get_findings`
Retrieve and filter GuardDuty findings
```python
{
    "detector_id": "string",
    "finding_criteria": {
        "severity": ["HIGH", "MEDIUM", "LOW"],
        "type": ["ThreatType"],
        "updated_at": {"gte": timestamp, "lte": timestamp}
    },
    "max_results": 50
}
```

### `get_malware_scans`
Check malware scan results
```python
{
    "detector_id": "string", 
    "scan_id": "optional_scan_id",
    "max_results": 50
}
```

### `start_malware_scan`
Initiate malware scan on resources
```python
{
    "detector_id": "string",
    "resource_arn": "arn:aws:ec2:region:account:instance/i-1234567890abcdef0"
}
```

### `get_detector_status`
Get GuardDuty detector configuration
```python
{
    "detector_id": "string"
}
```

### `generate_threat_report`
Create comprehensive security reports
```python
{
    "detector_id": "string",
    "time_range": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-07T23:59:59Z"
    },
    "format": "summary" | "json"
}
```

### `list_detectors`
List all GuardDuty detectors in the current region
```python
{}
```

## MCP Server Capabilities

### Security Data Access
- **Findings Retrieval**: Access GuardDuty findings with flexible filtering
- **Malware Scanning**: Retrieve and initiate malware scans
- **Detector Management**: Query detector status and configuration
- **Threat Reporting**: Generate comprehensive threat intelligence reports

### Integration Features
- **Standard MCP Protocol**: Compatible with any MCP-enabled AI assistant
- **Secure Access**: Controlled API access through well-defined tools
- **Flexible Filtering**: Advanced query capabilities for targeted data retrieval
- **JSON Responses**: Structured data format for easy processing

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone <repository>
cd guardduty-agent

# Install with development dependencies
pip install -e ".[dev]"

# Or with poetry
poetry install --with dev
```

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=guardduty_agent

# Run specific test file
pytest tests/test_guardduty_client.py
```

### Code Quality
```bash
# Format code
black guardduty_agent/ tests/

# Lint code
ruff check guardduty_agent/ tests/

# Type checking
mypy guardduty_agent/
```

### Project Structure
```
guardduty-agent/
├── guardduty_agent/
│   ├── __init__.py
│   ├── mcp_server.py         # MCP server implementation
│   ├── guardduty_client.py   # AWS GuardDuty client (boto3)
│   ├── config.py             # Configuration management
│   └── cli.py                # Command-line interface
├── tests/
│   ├── __init__.py
│   ├── test_guardduty_client.py
│   └── test_config.py
├── pyproject.toml            # Project configuration
├── .env.example              # Environment template
└── README.md
```

## Security Considerations

### IAM Permissions
The agent requires the following AWS IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "guardduty:GetFindings",
        "guardduty:ListFindings", 
        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "guardduty:DescribeMalwareScans",
        "guardduty:StartMalwareScan"
      ],
      "Resource": "*"
    }
  ]
}
```

### Best Practices
- **IAM Roles**: Use IAM roles instead of access keys when possible
- **Least Privilege**: Grant only the minimum required permissions
- **Environment Variables**: Store sensitive configuration in environment variables
- **Audit Logging**: Enable audit logging for compliance requirements
- **Encryption**: All API communications are encrypted in transit

## Integration Examples

### MCP Server Usage
```python
import asyncio
from guardduty_agent.mcp_server import GuardDutyMCPServer

async def main():
    # Start MCP server
    server = GuardDutyMCPServer()
    await server.run_server()

asyncio.run(main())
```

### Custom Tool Integration
```python
from guardduty_agent.guardduty_client import GuardDutyClient

async def custom_security_check():
    client = GuardDutyClient("us-east-1")
    
    # Get high-severity findings
    findings = await client.get_findings(
        detector_id="detector-123",
        finding_criteria={"severity": ["HIGH"]},
        max_results=10
    )
    
    return findings
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | us-east-1 | AWS region |
| `AWS_PROFILE` | - | AWS profile name |
| `AWS_ACCESS_KEY_ID` | - | AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | - | AWS secret access key |
| `GUARDDUTY_DETECTOR_ID` | - | GuardDuty detector ID |
| `GUARDDUTY_MAX_RESULTS` | 50 | Default max results |
| `LOG_LEVEL` | INFO | Logging level |

## Troubleshooting

### Common Issues

1. **AWS Credentials Not Found**
   - Ensure AWS credentials are configured
   - Check IAM permissions
   - Verify region settings

2. **GuardDuty Detector Not Found**
   - Confirm detector ID is correct
   - Check if GuardDuty is enabled in the region
   - Verify IAM permissions for GuardDuty

3. **MCP Connection Issues**
   - Ensure MCP client is properly configured
   - Check server process is running
   - Verify tool permissions

### Getting Help

For issues and support:
- Check the [GitHub Issues](https://github.com/your-org/guardduty-agent/issues)
- Review AWS GuardDuty documentation
- Consult MCP documentation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Ensure all tests pass and code is formatted
5. Submit a pull request

## License

MIT License - see LICENSE file for details