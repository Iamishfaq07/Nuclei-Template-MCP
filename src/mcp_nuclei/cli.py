"""Command line interface for mcp-nuclei."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from mcp_nuclei import __version__
from mcp_nuclei.config import Config, ConfigError, load_config, resolve_model
from mcp_nuclei.core import validator
from mcp_nuclei.core.batch import run_batch
from mcp_nuclei.core.generator import (
    GenerationError,
    GenerationResult,
    build_prepared_prompt,
    generate_from_capture,
    load_captures,
)
from mcp_nuclei.core.improver import improve_template
from mcp_nuclei.mcp.client import MCPClient, MCPClientError, get_client

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


def _load_config_or_exit(config_path: Optional[Path]) -> Config:
    try:
        return load_config(config_path)
    except ConfigError as exc:
        error_console.print(f"[bold red]Config error:[/bold red] {exc}")
        raise typer.Exit(code=1)


def _client_or_exit(backend: str, model: Optional[str]) -> MCPClient:
    try:
        return get_client(backend, model=model)
    except MCPClientError as exc:
        error_console.print(f"[bold red]MCP client error:[/bold red] {exc}")
        raise typer.Exit(code=1)


def _render_template(result: GenerationResult) -> None:
    syntax = Syntax(result.template_yaml, "yaml", theme="monokai", line_numbers=False, word_wrap=True)
    title = result.template_dict.get("id", "template")
    if result.refined:
        title = f"{title} (refined)"
    console.print(Panel(syntax, title=title, border_style="cyan"))


def _emit_result(
    result: GenerationResult,
    output: Optional[Path],
    show: bool,
    as_json: bool,
) -> None:
    """Write and/or display a single generation result."""
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.template_yaml, encoding="utf-8")

    if as_json:
        payload = {
            "id": result.template_dict.get("id"),
            "detected_type": result.detected_type,
            "refined": result.refined,
            "output": str(output) if output else None,
            "template": result.template_yaml,
        }
        console.print_json(json.dumps(payload))
        return

    if result.detected_type:
        console.print(f"[dim]Vulnerability type:[/dim] [bold]{result.detected_type}[/bold]")
    if output:
        console.print(f"[bold green]Template written to[/bold green] {output}")
    if show or not output:
        _render_template(result)


@app.command()
def generate(
    request: Path = typer.Option(
        ...,
        "--request",
        "-r",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a capture file: raw HTTP request, curl command, HAR, or Burp XML.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Where to write the template. Prints to stdout if omitted."
    ),
    response: Optional[Path] = typer.Option(
        None, "--response", exists=True, dir_okay=False, readable=True,
        help="Optional raw HTTP response file (raw format only) for more context.",
    ),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help='Vulnerability description, e.g. "IDOR in order endpoint".'
    ),
    vuln_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Force a vuln-specific prompt (idor, sqli, xss, ssrf, xxe, lfi, "
        "open-redirect, ssti, auth-bypass, cors, cmdi). Auto-detected from --description otherwise.",
    ),
    fmt: str = typer.Option("auto", "--format", "-f", help="Input format: auto, raw, curl, har, burp."),
    auto_classify: Optional[bool] = typer.Option(
        None, "--auto-classify/--no-auto-classify",
        help="Ask MCP to classify the vuln type when no --type/--description hint is given.",
    ),
    refine: Optional[bool] = typer.Option(
        None, "--refine/--no-refine", help="Run a second self-critique pass to harden the template."
    ),
    validate: bool = typer.Option(
        False, "--validate", help="Validate the result with the local `nuclei` binary if installed."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the assembled MCP prompt and exit without calling the backend."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit the result as JSON."),
    template_id: Optional[str] = typer.Option(None, "--id", help="Explicit template id."),
    author: Optional[str] = typer.Option(None, "--author", help="Author name to embed."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Severity (info/low/medium/high/critical)."),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags to merge in."),
    backend: Optional[str] = typer.Option(None, "--backend", help="MCP backend: auto, anthropic, openai."),
    model: Optional[str] = typer.Option(None, "--model", help="Model id for the chosen backend."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to a config file."),
    show: bool = typer.Option(True, "--show/--no-show", help="Print the template to the terminal."),
) -> None:
    """Generate a Nuclei template from a captured request via MCP-driven reasoning."""
    config = _load_config_or_exit(config_path)
    author = author or config.author
    severity = severity or config.severity
    tags = tags or config.tags
    refine = config.refine if refine is None else refine
    auto_classify = config.auto_classify if auto_classify is None else auto_classify

    try:
        captures = load_captures(request, response_path=response, fmt=fmt)
    except GenerationError as exc:
        error_console.print(f"[bold red]Failed to load request:[/bold red] {exc}")
        raise typer.Exit(code=1)
    if not captures:
        error_console.print(f"[bold red]No requests found in[/bold red] {request}")
        raise typer.Exit(code=1)
    capture = captures[0]

    if dry_run:
        prepared = build_prepared_prompt(
            request=capture.request, response=capture.response,
            description=description, vuln_type=vuln_type,
        )
        console.print(Panel(prepared.system_prompt, title="SYSTEM PROMPT", border_style="magenta"))
        console.print(Panel(prepared.user_prompt, title="USER PROMPT", border_style="blue"))
        if prepared.detected_type:
            console.print(f"[dim]Detected type:[/dim] [bold]{prepared.detected_type}[/bold]")
        return

    client = _client_or_exit(backend or config.backend, model or resolve_model(config))

    try:
        with console.status("[bold cyan]Analyzing request and generating template..."):
            result = generate_from_capture(
                capture, client=client, description=description, vuln_type=vuln_type,
                template_id=template_id, author=author, severity=severity, tags=tags,
                auto_classify=auto_classify, refine=bool(refine),
            )
    except GenerationError as exc:
        error_console.print(f"[bold red]Failed to generate template:[/bold red] {exc}")
        raise typer.Exit(code=1)

    _emit_result(result, output, show, as_json)

    if validate:
        _run_validation(result.template_yaml)


@app.command()
def improve(
    template: Path = typer.Option(
        ..., "--template", "-i", exists=True, dir_okay=False, readable=True,
        help="Path to an existing Nuclei template to improve.",
    ),
    request: Optional[Path] = typer.Option(
        None, "--request", "-r", exists=True, dir_okay=False, readable=True,
        help="Optional original capture file for extra context.",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Where to write the improved template."),
    fmt: str = typer.Option("auto", "--format", "-f", help="Format of --request: auto, raw, curl, har, burp."),
    validate: bool = typer.Option(False, "--validate", help="Validate the result with the `nuclei` binary."),
    as_json: bool = typer.Option(False, "--json", help="Emit the result as JSON."),
    backend: Optional[str] = typer.Option(None, "--backend", help="MCP backend: auto, anthropic, openai."),
    model: Optional[str] = typer.Option(None, "--model", help="Model id for the chosen backend."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to a config file."),
    show: bool = typer.Option(True, "--show/--no-show", help="Print the template to the terminal."),
) -> None:
    """Review and harden an existing Nuclei template via MCP-driven critique."""
    config = _load_config_or_exit(config_path)
    client = _client_or_exit(backend or config.backend, model or resolve_model(config))

    try:
        with console.status("[bold cyan]Reviewing and improving template..."):
            result = improve_template(template_path=template, client=client, request_path=request, fmt=fmt)
    except GenerationError as exc:
        error_console.print(f"[bold red]Failed to improve template:[/bold red] {exc}")
        raise typer.Exit(code=1)

    _emit_result(result, output, show, as_json)
    if validate:
        _run_validation(result.template_yaml)


@app.command()
def batch(
    directory: Path = typer.Option(
        ..., "--dir", "-D", exists=True, file_okay=False, help="Directory of capture files to process."
    ),
    output_dir: Path = typer.Option(
        ..., "--output-dir", "-O", help="Directory to write generated templates into."
    ),
    fmt: str = typer.Option("auto", "--format", "-f", help="Input format: auto, raw, curl, har, burp."),
    refine: Optional[bool] = typer.Option(None, "--refine/--no-refine", help="Run a self-critique pass on each."),
    auto_classify: Optional[bool] = typer.Option(
        None, "--auto-classify/--no-auto-classify", help="Classify each request's vuln type via MCP."
    ),
    author: Optional[str] = typer.Option(None, "--author", help="Author name to embed."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Severity to embed."),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags to merge in."),
    backend: Optional[str] = typer.Option(None, "--backend", help="MCP backend: auto, anthropic, openai."),
    model: Optional[str] = typer.Option(None, "--model", help="Model id for the chosen backend."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to a config file."),
) -> None:
    """Generate templates for every capture file in a directory."""
    config = _load_config_or_exit(config_path)
    client = _client_or_exit(backend or config.backend, model or resolve_model(config))

    try:
        with console.status("[bold cyan]Processing batch..."):
            summary = run_batch(
                directory, client=client, output_dir=output_dir, fmt=fmt,
                author=author or config.author, severity=severity or config.severity,
                tags=tags or config.tags,
                auto_classify=config.auto_classify if auto_classify is None else auto_classify,
                refine=config.refine if refine is None else refine,
            )
    except GenerationError as exc:
        error_console.print(f"[bold red]Batch failed:[/bold red] {exc}")
        raise typer.Exit(code=1)

    table = Table(title="Batch results")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Output / Error")
    for item in summary.items:
        if item.ok:
            table.add_row(item.label or item.source.name, "[green]ok[/green]",
                          str(item.output_path) if item.output_path else "-")
        else:
            table.add_row(item.label or item.source.name, "[red]failed[/red]", (item.error or "")[:80])
    console.print(table)
    console.print(f"[bold]{summary.succeeded} succeeded, {summary.failed} failed[/bold]")
    if summary.failed and not summary.succeeded:
        raise typer.Exit(code=1)


@app.command()
def validate(
    template: Path = typer.Option(
        ..., "--template", "-i", exists=True, dir_okay=False, readable=True,
        help="Path to a Nuclei template to validate.",
    ),
) -> None:
    """Validate a template against the local `nuclei` binary."""
    if not validator.is_available():
        error_console.print(
            "[bold yellow]nuclei binary not found on PATH.[/bold yellow] "
            "Install it from https://github.com/projectdiscovery/nuclei to enable validation."
        )
        raise typer.Exit(code=2)
    _run_validation_file(template)


def _run_validation(template_yaml: str) -> None:
    result = validator.validate_yaml(template_yaml)
    _report_validation(result)


def _run_validation_file(path: Path) -> None:
    result = validator.validate_file(path)
    _report_validation(result)
    if not result.ok:
        raise typer.Exit(code=1)


def _report_validation(result: validator.ValidationResult) -> None:
    if not result.available:
        console.print(f"[yellow]Validation skipped:[/yellow] {result.detail}")
        return
    if result.ok:
        console.print("[bold green]nuclei validation passed.[/bold green]")
    else:
        error_console.print("[bold red]nuclei validation failed:[/bold red]")
        error_console.print(result.output or result.detail)


if __name__ == "__main__":
    app()
