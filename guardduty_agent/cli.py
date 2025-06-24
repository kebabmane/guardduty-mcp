"""Command-line interface for GuardDuty MCP Server."""

import asyncio
import logging
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.prompt import Prompt

from .mcp_server import GuardDutyMCPServer
from .config import get_config, validate_config

# Initialize rich console
console = Console()
app = typer.Typer(
    name="guardduty-agent",
    help="AWS GuardDuty MCP Server",
    add_completion=False,
)


def setup_logging(level: str = "INFO") -> None:
    """Set up logging with rich handler."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@app.command()
def server(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Start the GuardDuty MCP server."""
    setup_logging("DEBUG" if verbose else "INFO")
    
    try:
        validate_config()
        asyncio.run(_run_server())
        
    except Exception as e:
        raise typer.Exit(1)




@app.command()
def list_detectors(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """List all GuardDuty detectors in the current region."""
    setup_logging("DEBUG" if verbose else "INFO")
    
    try:
        validate_config()
        asyncio.run(_list_detectors())
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


async def _run_server() -> None:
    """Run the MCP server."""
    # Don't print anything to stdout when running as MCP server
    # Claude Desktop expects pure JSON over stdio
    # Redirect stderr to devnull to suppress all error messages
    import sys
    import os
    import logging
    
    # Save original stderr and redirect to devnull
    original_stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')
    
    # Disable all logging to avoid interfering with MCP protocol
    logging.getLogger().setLevel(logging.CRITICAL)
    logging.getLogger().handlers.clear()
    
    try:
        server = GuardDutyMCPServer()
        await server.run_server()
    finally:
        # Restore stderr
        sys.stderr = original_stderr


async def _list_detectors() -> None:
    """List GuardDuty detectors."""
    from .guardduty_client import GuardDutyClient
    
    config = get_config()
    client = GuardDutyClient(config.aws.region)
    
    with console.status("[blue]Fetching detectors...[/blue]"):
        detectors = await client.list_detectors()
    
    if detectors["count"] == 0:
        console.print("[yellow]No GuardDuty detectors found in the current region.[/yellow]")
        return
    
    console.print(f"[green]Found {detectors['count']} detector(s):[/green]")
    for detector_id in detectors["detector_ids"]:
        console.print(f"  • {detector_id}")




def main() -> None:
    """Main CLI entry point."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()