"""Command line interface for mcp-nuclei."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from mcp_nuclei import __version__
from mcp_nuclei.core.generator import GenerationError, generate_template
from mcp_nuclei.mcp.client import MCPClientError, get_default_client

app = typer.Typer(
    name="mcp-nuclei",
    help="Generate high-quality Nuclei templates from raw HTTP requests using MCP-driven reasoning.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
error_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"mcp-nuclei {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """mcp-nuclei: an MCP-powered Nuclei template generator."""


@app.command()
def generate(
    request: Path = typer.Option(
        ...,
        "--request",
        "-r",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a raw HTTP request file (e.g. captured from Burp Suite / ZAP).",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the generated template. Prints to stdout if omitted.",
    ),
    response: Optional[Path] = typer.Option(
        None,
        "--response",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Optional raw HTTP response file, giving MCP more context to reason about.",
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description",
        "-d",
        help='Short description of the vulnerability, e.g. "IDOR in order endpoint".',
    ),
    vuln_type: Optional[str] = typer.Option(
        None,
        "--type",
        "-t",
        help="Force a vulnerability-specific prompt (idor, sqli, xss). Auto-detected from "
        "--description otherwise.",
    ),
    template_id: Optional[str] = typer.Option(
        None,
        "--id",
        help="Explicit template id. Derived from the description/request otherwise.",
    ),
    author: Optional[str] = typer.Option(None, "--author", help="Author name to embed in the template."),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        help="Severity to embed (info, low, medium, high, critical).",
    ),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags to merge into the template."),
    show: bool = typer.Option(True, "--show/--no-show", help="Print the generated template to the terminal."),
) -> None:
    """Generate a Nuclei template from a raw HTTP request via MCP-driven reasoning."""
    try:
        client = get_default_client()
    except MCPClientError as exc:
        error_console.print(f"[bold red]MCP client error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    try:
        with console.status("[bold cyan]Analyzing request and generating template..."):
            result = generate_template(
                request_path=request,
                client=client,
                response_path=response,
                description=description,
                vuln_type=vuln_type,
                template_id=template_id,
                author=author,
                severity=severity,
                tags=tags,
            )
    except GenerationError as exc:
        error_console.print(f"[bold red]Failed to generate template:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if result.detected_type:
        console.print(f"[dim]Detected vulnerability type:[/dim] [bold]{result.detected_type}[/bold]")

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.template_yaml, encoding="utf-8")
        console.print(f"[bold green]Template written to[/bold green] {output}")

    if show or not output:
        syntax = Syntax(result.template_yaml, "yaml", theme="monokai", line_numbers=False, word_wrap=True)
        console.print(Panel(syntax, title=result.template_dict.get("id", "template"), border_style="cyan"))


if __name__ == "__main__":
    app()
