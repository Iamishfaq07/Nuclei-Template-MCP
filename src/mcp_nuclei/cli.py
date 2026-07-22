"""Command line interface for mcp-nuclei."""
from __future__ import annotations

import difflib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from mcp_nuclei import __version__
from mcp_nuclei.config import Config, ConfigError, load_config, resolve_model
from mcp_nuclei.core import validator
from mcp_nuclei.core.batch import run_batch
from mcp_nuclei.core.builder import BuildError
from mcp_nuclei.core.dedup import find_duplicates
from mcp_nuclei.core.eval import run_eval
from mcp_nuclei.core.generator import (
    GenerationError,
    GenerationResult,
    build_prepared_prompt,
    explain_template,
    generate_from_capture,
    load_captures,
)
from mcp_nuclei.core.history import RunRecord, default_history_path, list_runs, record_run
from mcp_nuclei.core.improver import improve_template
from mcp_nuclei.core.lint import lint_template
from mcp_nuclei.core.notify import notify_webhook
from mcp_nuclei.core.parser import ParseError
from mcp_nuclei.core.verify import VerifyResult, read_targets_file, verify_targets, verify_yaml
from mcp_nuclei.core.watch import watch_directory
from mcp_nuclei.core.workflow import build_workflow
from mcp_nuclei.core.workflow import to_yaml as workflow_to_yaml
from mcp_nuclei.mcp.cache import CachingMCPClient
from mcp_nuclei.mcp.client import MCPClient, MCPClientError, get_client
from mcp_nuclei.mcp.metering import MeteringMCPClient, UsageTotals
from mcp_nuclei.mcp.retry import RetryingMCPClient

app = typer.Typer(
    name="mcp-nuclei",
    help="Generate high-quality Nuclei templates from raw HTTP requests using MCP-driven reasoning.",
    add_completion=True,
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


def _prepare_client(
    backend: str, model: Optional[str], *, cache: bool, cost: bool, retries: int = 0
) -> tuple[MCPClient, Optional[MeteringMCPClient]]:
    """Resolve a backend client, optionally wrapping it for metering/retry/caching.

    Layering (outermost first): cache -> retry -> metering -> real backend.
    A cache hit short-circuits before retry or metering ever run (no real
    work happened, so nothing to retry and no cost). Metering sits directly
    on the real client so retried attempts are metered individually and
    a failed attempt (which raises before returning) is never counted.
    """
    client: MCPClient = _client_or_exit(backend, model)
    metering: Optional[MeteringMCPClient] = None
    if cost:
        metering = MeteringMCPClient(client)
        client = metering
    if retries > 0:
        client = RetryingMCPClient(client, max_retries=retries)
    if cache:
        client = CachingMCPClient(client)
    return client, metering


def _report_cost(totals: UsageTotals) -> None:
    if totals.call_count == 0:
        console.print("[dim]No billable MCP calls were made (cached, or usage unavailable for this backend).[/dim]")
        return
    line = f"[dim]{totals.call_count} MCP call(s) · {totals.input_tokens} input / {totals.output_tokens} output tokens"
    if totals.has_cost_estimate:
        line += f" · ~${totals.estimated_cost_usd:.4f} estimated"
    line += "[/dim]"
    console.print(line)


def _record_history(
    command: str,
    result: Optional[GenerationResult],
    *,
    backend: str,
    model: Optional[str],
    metering: Optional[MeteringMCPClient],
    source_label: Optional[str],
) -> None:
    totals = metering.totals if metering else None
    record_run(
        RunRecord(
            command=command,
            template_id=(result.template_dict.get("id") if result else None),
            detected_type=(result.detected_type if result else None),
            source_label=source_label,
            backend=backend,
            model=model,
            input_tokens=(totals.input_tokens if totals else None),
            output_tokens=(totals.output_tokens if totals else None),
            estimated_cost_usd=(totals.estimated_cost_usd if totals and totals.has_cost_estimate else None),
        )
    )


def _report_verify(result: VerifyResult, *, label: str = "target", expect_no_match: bool = False) -> None:
    if not result.available:
        console.print(f"[yellow]Live verification skipped:[/yellow] {result.detail}")
        return
    if not result.ran:
        error_console.print(f"[bold red]Live verification failed to run:[/bold red] {result.detail}")
        return

    if expect_no_match:
        if result.matched:
            error_console.print(
                f"[bold red]Negative check FAILED against {label}:[/bold red] the template matched "
                f"({len(result.matches)} match(es)) — this looks like a false positive."
            )
        else:
            console.print(f"[bold green]Negative check passed against {label}:[/bold green] no match, as expected.")
        return

    if result.matched:
        console.print(
            f"[bold green]Live verification: matched against {label}[/bold green] "
            f"({len(result.matches)} match(es))."
        )
    else:
        console.print(
            f"[bold yellow]Live verification: no match against {label}.[/bold yellow] "
            "The template may be too strict, the target may not be vulnerable, or it may be unreachable."
        )
    if result.detail:
        console.print(f"[dim]{result.detail}[/dim]")


def _print_explanation(text: str) -> None:
    console.print(Panel(text, title="Why this template", border_style="green"))


def _render_diff(before: str, after: str, label: str) -> None:
    lines = list(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"{label} (original)",
            tofile=f"{label} (improved)",
        )
    )
    if not lines:
        console.print("[dim]No differences.[/dim]")
        return
    syntax = Syntax("".join(lines), "diff", theme="monokai", word_wrap=True)
    console.print(Panel(syntax, title="diff", border_style="yellow"))


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


def _notify_or_warn(webhook: Optional[str], text: str, extra: Optional[dict] = None) -> None:
    if not webhook:
        return
    outcome = notify_webhook(webhook, text, extra=extra)
    if not outcome.sent:
        error_console.print(f"[yellow]Webhook notification failed:[/yellow] {outcome.error}")


@app.command()
def generate(
    request: Path = typer.Option(
        ...,
        "--request",
        "-r",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to a capture file: raw HTTP request, curl command, HAR, Burp XML, or OpenAPI/Swagger spec.",
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
    fmt: str = typer.Option("auto", "--format", "-f", help="Input format: auto, raw, curl, har, burp, openapi."),
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
    verify_url: Optional[str] = typer.Option(
        None, "--verify-url",
        help="Live-test the template against this URL via the local `nuclei` binary. "
        "Fires real HTTP requests — only use targets you're authorized to test.",
    ),
    verify_safe_url: Optional[str] = typer.Option(
        None, "--verify-safe-url",
        help="Live-test against a known-patched/safe URL and confirm the template does NOT match "
        "(a false-positive regression check). Fires real HTTP requests.",
    ),
    verify_urls_file: Optional[Path] = typer.Option(
        None, "--verify-urls-file", exists=True, dir_okay=False,
        help="Verify against every URL listed (one per line) in this file instead of a single --verify-url.",
    ),
    verify_args: Optional[str] = typer.Option(
        None, "--verify-args", help="Extra flags to pass through to `nuclei` during verification (shell-quoted)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the assembled MCP prompt and exit without calling the backend."
    ),
    explain: bool = typer.Option(
        False, "--explain", help="Ask MCP for a short rationale for the template (extra API call)."
    ),
    cache: bool = typer.Option(
        False, "--cache", help="Reuse a cached response for an identical prompt instead of calling the backend."
    ),
    cost: bool = typer.Option(False, "--cost", help="Report token usage and estimated cost for this run."),
    retries: int = typer.Option(0, "--retries", help="Retry a failed MCP call this many times with backoff."),
    history: bool = typer.Option(False, "--history", help="Record this run in the local run history (metadata only, no request content)."),
    notify_webhook_url: Optional[str] = typer.Option(
        None, "--notify-webhook", help="POST a summary to this webhook URL (Slack-compatible) after completion."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit the result as JSON."),
    template_id: Optional[str] = typer.Option(None, "--id", help="Explicit template id."),
    author: Optional[str] = typer.Option(None, "--author", help="Author name to embed."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Severity (info/low/medium/high/critical)."),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags to merge in."),
    cve_id: Optional[str] = typer.Option(None, "--cve-id", help="Attach a known CVE id to info.classification."),
    cwe_id: Optional[str] = typer.Option(None, "--cwe-id", help="Attach a known CWE id to info.classification."),
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
    resolved_backend = backend or config.backend
    resolved_model = model or resolve_model(config)

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

    client, metering = _prepare_client(resolved_backend, resolved_model, cache=cache, cost=cost, retries=retries)

    try:
        with console.status("[bold cyan]Analyzing request and generating template..."):
            result = generate_from_capture(
                capture, client=client, description=description, vuln_type=vuln_type,
                template_id=template_id, author=author, severity=severity, tags=tags,
                auto_classify=auto_classify, refine=bool(refine), cve_id=cve_id, cwe_id=cwe_id,
            )
    except GenerationError as exc:
        error_console.print(f"[bold red]Failed to generate template:[/bold red] {exc}")
        raise typer.Exit(code=1)

    _emit_result(result, output, show, as_json)

    if explain:
        try:
            with console.status("[bold cyan]Explaining template..."):
                rationale = explain_template(result.template_yaml, capture.request, client)
            _print_explanation(rationale)
        except GenerationError as exc:
            error_console.print(f"[bold red]Failed to generate explanation:[/bold red] {exc}")

    if validate:
        _run_validation(result.template_yaml)

    if verify_url:
        with console.status(f"[bold cyan]Verifying against {verify_url}..."):
            verify_result = verify_yaml(result.template_yaml, verify_url, extra_args=verify_args)
        _report_verify(verify_result, label=verify_url)

    if verify_safe_url:
        with console.status(f"[bold cyan]Checking for false positives against {verify_safe_url}..."):
            safe_result = verify_yaml(result.template_yaml, verify_safe_url, extra_args=verify_args)
        _report_verify(safe_result, label=verify_safe_url, expect_no_match=True)

    if verify_urls_file:
        urls = read_targets_file(verify_urls_file)
        with console.status(f"[bold cyan]Verifying against {len(urls)} target(s)..."):
            multi_results = verify_targets(result.template_yaml, urls, extra_args=verify_args)
        matched = sum(1 for r in multi_results.values() if r.matched)
        console.print(f"[bold]{matched}/{len(urls)} target(s) matched.[/bold]")
        for url, r in multi_results.items():
            status = "[green]matched[/green]" if r.matched else "[yellow]no match[/yellow]"
            console.print(f"  {url}: {status}")

    if cost and metering:
        _report_cost(metering.totals)

    if history:
        _record_history("generate", result, backend=resolved_backend, model=resolved_model, metering=metering, source_label=request.name)

    _notify_or_warn(
        notify_webhook_url,
        f"mcp-nuclei generate: {result.template_dict.get('id')} ({result.detected_type or 'unclassified'})",
        extra={"template_id": result.template_dict.get("id"), "source": request.name},
    )


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
    fmt: str = typer.Option("auto", "--format", "-f", help="Format of --request: auto, raw, curl, har, burp, openapi."),
    validate: bool = typer.Option(False, "--validate", help="Validate the result with the `nuclei` binary."),
    verify_url: Optional[str] = typer.Option(
        None, "--verify-url",
        help="Live-test the result against this URL via the local `nuclei` binary. "
        "Fires real HTTP requests — only use targets you're authorized to test.",
    ),
    verify_safe_url: Optional[str] = typer.Option(
        None, "--verify-safe-url",
        help="Live-test against a known-patched/safe URL and confirm the template does NOT match.",
    ),
    verify_args: Optional[str] = typer.Option(
        None, "--verify-args", help="Extra flags to pass through to `nuclei` during verification (shell-quoted)."
    ),
    diff: bool = typer.Option(False, "--diff", help="Show a diff between the original and improved template."),
    cache: bool = typer.Option(
        False, "--cache", help="Reuse a cached response for an identical prompt instead of calling the backend."
    ),
    cost: bool = typer.Option(False, "--cost", help="Report token usage and estimated cost for this run."),
    retries: int = typer.Option(0, "--retries", help="Retry a failed MCP call this many times with backoff."),
    history: bool = typer.Option(False, "--history", help="Record this run in the local run history."),
    as_json: bool = typer.Option(False, "--json", help="Emit the result as JSON."),
    backend: Optional[str] = typer.Option(None, "--backend", help="MCP backend: auto, anthropic, openai."),
    model: Optional[str] = typer.Option(None, "--model", help="Model id for the chosen backend."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to a config file."),
    show: bool = typer.Option(True, "--show/--no-show", help="Print the template to the terminal."),
) -> None:
    """Review and harden an existing Nuclei template via MCP-driven critique."""
    config = _load_config_or_exit(config_path)
    resolved_backend = backend or config.backend
    resolved_model = model or resolve_model(config)
    client, metering = _prepare_client(resolved_backend, resolved_model, cache=cache, cost=cost, retries=retries)

    original_text = template.read_text(encoding="utf-8") if diff else None

    try:
        with console.status("[bold cyan]Reviewing and improving template..."):
            result = improve_template(template_path=template, client=client, request_path=request, fmt=fmt)
    except GenerationError as exc:
        error_console.print(f"[bold red]Failed to improve template:[/bold red] {exc}")
        raise typer.Exit(code=1)

    _emit_result(result, output, show, as_json)

    if diff and original_text is not None:
        _render_diff(original_text, result.template_yaml, template.name)

    if validate:
        _run_validation(result.template_yaml)

    if verify_url:
        with console.status(f"[bold cyan]Verifying against {verify_url}..."):
            verify_result = verify_yaml(result.template_yaml, verify_url, extra_args=verify_args)
        _report_verify(verify_result, label=verify_url)

    if verify_safe_url:
        with console.status(f"[bold cyan]Checking for false positives against {verify_safe_url}..."):
            safe_result = verify_yaml(result.template_yaml, verify_safe_url, extra_args=verify_args)
        _report_verify(safe_result, label=verify_safe_url, expect_no_match=True)

    if cost and metering:
        _report_cost(metering.totals)

    if history:
        _record_history("improve", result, backend=resolved_backend, model=resolved_model, metering=metering, source_label=template.name)


@app.command()
def batch(
    directory: Path = typer.Option(
        ..., "--dir", "-D", exists=True, file_okay=False, help="Directory of capture files to process."
    ),
    output_dir: Path = typer.Option(
        ..., "--output-dir", "-O", help="Directory to write generated templates into."
    ),
    fmt: str = typer.Option("auto", "--format", "-f", help="Input format: auto, raw, curl, har, burp, openapi."),
    refine: Optional[bool] = typer.Option(None, "--refine/--no-refine", help="Run a self-critique pass on each."),
    auto_classify: Optional[bool] = typer.Option(
        None, "--auto-classify/--no-auto-classify", help="Classify each request's vuln type via MCP."
    ),
    author: Optional[str] = typer.Option(None, "--author", help="Author name to embed."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Severity to embed."),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags to merge in."),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of captures to process concurrently."),
    cache: bool = typer.Option(
        False, "--cache", help="Reuse cached responses for identical prompts instead of calling the backend."
    ),
    cost: bool = typer.Option(False, "--cost", help="Report total token usage and estimated cost for the batch."),
    retries: int = typer.Option(0, "--retries", help="Retry a failed MCP call this many times with backoff."),
    history: bool = typer.Option(False, "--history", help="Record this run in the local run history."),
    notify_webhook_url: Optional[str] = typer.Option(
        None, "--notify-webhook", help="POST a summary to this webhook URL (Slack-compatible) after completion."
    ),
    backend: Optional[str] = typer.Option(None, "--backend", help="MCP backend: auto, anthropic, openai."),
    model: Optional[str] = typer.Option(None, "--model", help="Model id for the chosen backend."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to a config file."),
) -> None:
    """Generate templates for every capture file in a directory."""
    config = _load_config_or_exit(config_path)
    resolved_backend = backend or config.backend
    resolved_model = model or resolve_model(config)
    client, metering = _prepare_client(resolved_backend, resolved_model, cache=cache, cost=cost, retries=retries)

    try:
        with console.status("[bold cyan]Processing batch..."):
            summary = run_batch(
                directory, client=client, output_dir=output_dir, fmt=fmt,
                author=author or config.author, severity=severity or config.severity,
                tags=tags or config.tags,
                auto_classify=config.auto_classify if auto_classify is None else auto_classify,
                refine=config.refine if refine is None else refine,
                max_workers=max(1, workers),
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

    if cost and metering:
        _report_cost(metering.totals)

    if history:
        for item in summary.items:
            _record_history(
                "batch", item.result, backend=resolved_backend, model=resolved_model,
                metering=None, source_label=item.label or item.source.name,
            )
        if cost and metering:
            _record_history("batch-total", None, backend=resolved_backend, model=resolved_model, metering=metering, source_label=str(directory))

    _notify_or_warn(
        notify_webhook_url,
        f"mcp-nuclei batch on {directory}: {summary.succeeded} succeeded, {summary.failed} failed",
        extra={"succeeded": summary.succeeded, "failed": summary.failed},
    )

    if summary.failed and not summary.succeeded:
        raise typer.Exit(code=1)


@app.command()
def watch(
    directory: Path = typer.Option(
        ..., "--dir", "-D", exists=True, file_okay=False, help="Directory to watch for new/changed capture files."
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir", "-O", help="Directory to write generated templates into. Prints to stdout if omitted."
    ),
    fmt: str = typer.Option("auto", "--format", "-f", help="Input format: auto, raw, curl, har, burp, openapi."),
    poll_interval: float = typer.Option(2.0, "--poll-interval", help="Seconds between directory scans."),
    process_existing: bool = typer.Option(
        False, "--process-existing", help="Also process files already present when watch mode starts."
    ),
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
    """Watch a directory and generate a template whenever a new capture appears (Ctrl+C to stop)."""
    config = _load_config_or_exit(config_path)
    client, _ = _prepare_client(backend or config.backend, model or resolve_model(config), cache=False, cost=False)

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold cyan]Watching {directory} for new captures...[/bold cyan] (Ctrl+C to stop)")
    try:
        for item in watch_directory(
            directory,
            client=client,
            output_dir=output_dir,
            fmt=fmt,
            author=author or config.author,
            severity=severity or config.severity,
            tags=tags or config.tags,
            auto_classify=config.auto_classify if auto_classify is None else auto_classify,
            refine=config.refine if refine is None else refine,
            poll_interval=poll_interval,
            process_existing=process_existing,
        ):
            if item.ok and item.result is not None:
                console.print(f"[green]✓[/green] {item.label} -> {item.output_path or item.result.template_dict.get('id')}")
            else:
                error_console.print(f"[red]✗[/red] {item.label}: {item.error}")
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


@app.command()
def lint(
    template: Path = typer.Option(
        ..., "--template", "-i", exists=True, dir_okay=False, readable=True,
        help="Path to a Nuclei template to lint.",
    ),
) -> None:
    """Check a template against nuclei-templates style conventions (id format, tags, matchers, etc.)."""
    try:
        data = yaml.safe_load(template.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        error_console.print(f"[bold red]Invalid YAML:[/bold red] {exc}")
        raise typer.Exit(code=1)
    if not isinstance(data, dict):
        error_console.print("[bold red]Template is not a YAML mapping at the top level.[/bold red]")
        raise typer.Exit(code=1)

    issues = lint_template(data)
    if not issues:
        console.print("[bold green]No lint issues found.[/bold green]")
        return

    table = Table(title=f"Lint results for {template.name}")
    table.add_column("Level")
    table.add_column("Message")
    for issue in issues:
        level_style = "[bold red]error[/bold red]" if issue.level == "error" else "[yellow]warning[/yellow]"
        table.add_row(level_style, issue.message)
    console.print(table)

    if any(i.level == "error" for i in issues):
        raise typer.Exit(code=1)


@app.command()
def workflow(
    templates: list[Path] = typer.Option(
        ..., "--template", "-i", exists=True, dir_okay=False, readable=True,
        help="A template to include in the workflow. Repeat for multiple templates, in run order.",
    ),
    workflow_id: str = typer.Option(..., "--id", help="Id for the generated workflow."),
    name: str = typer.Option(..., "--name", help="Name for the generated workflow."),
    author: str = typer.Option("mcp-nuclei", "--author", help="Author name to embed."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Where to write the workflow YAML."),
) -> None:
    """Combine several existing templates into a Nuclei workflow file."""
    try:
        wf = build_workflow(templates, workflow_id=workflow_id, name=name, author=author)
    except (BuildError, ParseError) as exc:
        error_console.print(f"[bold red]Failed to build workflow:[/bold red] {exc}")
        raise typer.Exit(code=1)

    rendered = workflow_to_yaml(wf)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        console.print(f"[bold green]Workflow written to[/bold green] {output}")
    else:
        console.print(Syntax(rendered, "yaml", theme="monokai", word_wrap=True))


@app.command()
def dedup(
    template: Path = typer.Option(
        ..., "--template", "-i", exists=True, dir_okay=False, readable=True,
        help="Path to a (usually newly generated) template to check.",
    ),
    against: Path = typer.Option(
        ..., "--against", exists=True, file_okay=False,
        help="Local directory of existing templates to search (e.g. a nuclei-templates checkout).",
    ),
    threshold: float = typer.Option(0.3, "--threshold", help="Minimum similarity score (0-1) to report."),
) -> None:
    """Check a template against a local directory for likely near-duplicates."""
    try:
        data = yaml.safe_load(template.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        error_console.print(f"[bold red]Invalid YAML:[/bold red] {exc}")
        raise typer.Exit(code=1)
    if not isinstance(data, dict):
        error_console.print("[bold red]Template is not a YAML mapping at the top level.[/bold red]")
        raise typer.Exit(code=1)

    matches = find_duplicates(data, against, threshold=threshold)
    if not matches:
        console.print("[bold green]No likely duplicates found.[/bold green]")
        return

    table = Table(title="Possible duplicates")
    table.add_column("Score")
    table.add_column("Template")
    table.add_column("Path")
    table.add_column("Why")
    for match in matches:
        table.add_row(f"{match.score:.2f}", match.template_id, str(match.path), "; ".join(match.reasons))
    console.print(table)


@app.command(name="eval")
def eval_prompts(
    fixtures: Path = typer.Option(
        ..., "--fixtures", exists=True, file_okay=False, help="Directory of *.json fixture files."
    ),
    backend: Optional[str] = typer.Option(None, "--backend", help="MCP backend: auto, anthropic, openai."),
    model: Optional[str] = typer.Option(None, "--model", help="Model id for the chosen backend."),
    config_path: Optional[Path] = typer.Option(None, "--config", help="Path to a config file."),
) -> None:
    """Replay fixture requests through generation and check structural expectations (prompt regression check)."""
    config = _load_config_or_exit(config_path)
    client, _ = _prepare_client(backend or config.backend, model or resolve_model(config), cache=False, cost=False)

    try:
        with console.status("[bold cyan]Running eval fixtures..."):
            outcomes = run_eval(fixtures, client)
    except (NotADirectoryError, ValueError) as exc:
        error_console.print(f"[bold red]Failed to load fixtures:[/bold red] {exc}")
        raise typer.Exit(code=1)

    table = Table(title="Eval results")
    table.add_column("Case")
    table.add_column("Status")
    table.add_column("Details")
    failed = 0
    for outcome in outcomes:
        if outcome.passed:
            table.add_row(outcome.case.name, "[green]pass[/green]", outcome.template_id or "-")
        else:
            failed += 1
            details = outcome.error or "; ".join(outcome.reasons)
            table.add_row(outcome.case.name, "[red]fail[/red]", details)
    console.print(table)
    console.print(f"[bold]{len(outcomes) - failed}/{len(outcomes)} passed[/bold]")

    if failed:
        raise typer.Exit(code=1)


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", help="Maximum number of runs to show."),
) -> None:
    """Show recent runs recorded with --history (metadata only, stored locally)."""
    records = list_runs(limit=limit)
    if not records:
        console.print(
            f"[dim]No history recorded yet. Pass --history on generate/improve/batch to log runs "
            f"(stored at {default_history_path()}).[/dim]"
        )
        return

    table = Table(title="Run history")
    table.add_column("When")
    table.add_column("Command")
    table.add_column("Template")
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Tokens")
    table.add_column("Cost")
    for record in records:
        when = datetime.fromtimestamp(record.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        tokens = (
            f"{record.input_tokens}/{record.output_tokens}"
            if record.input_tokens is not None
            else "-"
        )
        cost = f"${record.estimated_cost_usd:.4f}" if record.estimated_cost_usd is not None else "-"
        table.add_row(when, record.command, record.template_id or "-", record.detected_type or "-",
                      record.source_label or "-", tokens, cost)
    console.print(table)


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
