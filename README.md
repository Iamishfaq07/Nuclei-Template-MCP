# mcp-nuclei

A smart [Nuclei](https://github.com/projectdiscovery/nuclei) template generator that uses MCP-driven LLM reasoning to turn a captured, vulnerable HTTP request (and optional response) into a high-quality, production-ready Nuclei YAML template — not a naive curl-to-yaml conversion.

Instead of just replaying a request and matching on a status code, `mcp-nuclei` reasons about *why* the request is vulnerable and produces templates with precise matchers, sensible extractors, parameterized variables, and false-positive-aware logic — the kind of template a careful human template author would write.

## Features

- **Multiple input formats** — raw HTTP requests, `curl` commands, HAR files (browser/Charles/Fiddler), Burp Suite XML exports, and OpenAPI/Swagger specs (one request per operation), all auto-detected.
- **`generate`** — turn one capture into a high-quality template.
- **`improve`** — review and harden an existing template via MCP critique, with a `--diff` view.
- **`batch`** — generate templates for a whole directory of captures at once, optionally concurrently (`--workers`).
- **`watch`** — auto-generate a template whenever a new capture file lands in a directory.
- **`validate`** — run the result through the real `nuclei` binary if installed.
- **`lint`** — check a template against nuclei-templates style conventions (id format, tags, matcher quality, hardcoded hosts).
- **`workflow`** — chain several existing templates into a Nuclei workflow file.
- **`dedup`** — check a new template against a local directory (e.g. a nuclei-templates checkout) for likely near-duplicates.
- **`eval`** — replay fixture requests through generation and assert structural expectations, to guard prompt quality as you tune `prompts/*.txt`.
- **`history`** — local, opt-in run log (metadata only — no request content) for cost/audit tracking.
- **Specialized reasoning** for 11 vuln classes: IDOR, SQLi, XSS, SSRF, XXE, LFI/traversal, open redirect, SSTI, auth bypass, CORS, and command injection — auto-detected from your description, forced with `--type`, or classified by the model itself (`--auto-classify`). Includes guidance for multi-step/chained templates and non-HTTP (`websocket:`) protocol blocks.
- **Self-critique** — `--refine` runs a second generate → critique → fix pass for tighter templates.
- **Live verification** — `--verify-url` actually runs the generated template against a real target via the `nuclei` binary and reports whether it matched. `--verify-safe-url` runs the same check against a known-patched target and confirms it does *not* match (a false-positive regression check). `--verify-urls-file` checks a whole list of targets. All opt-in; nothing fires without an explicit URL.
- **`--explain`** — a short, plain-language rationale for why the matchers prove the vulnerability, shown separately from the YAML.
- **`--cache` / `--cost` / `--retries`** — skip re-calling the backend for an identical prompt, see token usage + an estimated USD cost per run, and retry transient backend failures with backoff.
- **`--cve-id` / `--cwe-id`** — attach a known CVE/CWE to the template's `info.classification` block.
- **`--notify-webhook`** — POST a completion summary to a Slack-compatible webhook.
- **Plugin system** — third-party packages can register additional vuln-type prompts via a Python entry point, no fork required.
- **Pluggable backends** — Anthropic or any OpenAI-compatible endpoint (incl. local Ollama/LM Studio), or bring your own MCP agent.
- **Config file, `--dry-run`, `--json`, shell completion** — sensible defaults, prompt inspection, machine-readable output for CI, and `--install-completion` for your shell.
- **Docker image** and a **GitHub Action** (`workflow_dispatch`) to generate templates in CI.

## Why not just convert curl -> yaml?

Naive converters preserve every header and cookie verbatim and match on something generic like a 200 status code, which is both fragile (breaks the moment the target changes slightly) and noisy (false-positives on unrelated pages). `mcp-nuclei` instead:

- Strips the request down to what the vulnerability actually depends on
- Picks matchers that a patched target would *not* trigger
- Adds extractors when they add real detection value
- Uses Nuclei variables (`{{BaseURL}}`, `{{Hostname}}`, `{{interactsh-url}}`, custom `{{variable}}`s) instead of hardcoding the sample target
- Chooses an honest severity based on real-world impact
- Can actually prove it: `--verify-url` runs the template for real, and `--verify-safe-url` proves it doesn't false-positive on a patched target

## Installation

```bash
git clone https://github.com/Iamishfaq07/Nuclei-Template-MCP.git
cd Nuclei-Template-MCP
pip install -e .
```

Pick a backend and set the matching API key:

```bash
# Anthropic (default)
pip install -e ".[llm]"
export ANTHROPIC_API_KEY="sk-ant-..."

# or any OpenAI-compatible endpoint
pip install -e ".[openai]"
export OPENAI_API_KEY="sk-..."
# export OPENAI_BASE_URL="http://localhost:11434/v1"   # e.g. local Ollama
```

For development (tests, linting, type checking):

```bash
pip install -r requirements-dev.txt
```

Enable shell completion (optional):

```bash
mcp-nuclei --install-completion
```

## Usage

### Generate

From a raw HTTP request file (Burp/ZAP export), a curl command, a HAR file, a Burp XML export, or an OpenAPI/Swagger spec — the format is auto-detected:

```bash
mcp-nuclei generate --request examples/requests/idor-order-endpoint.req --output template.yaml
mcp-nuclei generate --request examples/requests/ssti-search.curl --type ssti
mcp-nuclei generate --request openapi.yaml --output template.yaml   # uses the first operation in the spec
```

> For a HAR, Burp, or OpenAPI file with many requests/operations, use `batch` (below) to generate one template per request.

Give it more context — a description and the observed response — for better reasoning, and prove the result actually works:

```bash
mcp-nuclei generate \
  --request examples/requests/idor-order-endpoint.req \
  --response examples/requests/idor-order-endpoint.resp \
  --description "IDOR in order endpoint - low-priv user can read other customers' orders" \
  --refine --validate \
  --verify-url https://staging.example.com --verify-safe-url https://patched-staging.example.com \
  --output template.yaml
```

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--type / -t` | Force a vuln-specific prompt (`idor`, `sqli`, `xss`, `ssrf`, `xxe`, `lfi`, `open-redirect`, `ssti`, `auth-bypass`, `cors`, `cmdi`, or any plugin-registered type). |
| `--format / -f` | `auto` (default), `raw`, `curl`, `har`, `burp`, `openapi`. |
| `--auto-classify` | Let the model classify the vuln type when you give no hint. |
| `--refine` | Second self-critique pass to harden the template. |
| `--validate` | Validate the result with the local `nuclei` binary. |
| `--verify-url URL` | Actually run the template against `URL` via `nuclei` and report the result. **Fires real requests — only use authorized targets.** |
| `--verify-safe-url URL` | Run against a known-patched/safe target and confirm it does **not** match (false-positive check). |
| `--verify-urls-file FILE` | Verify against every URL listed (one per line) in a file. |
| `--dry-run` | Print the assembled MCP prompt and exit (no API call). |
| `--explain` | Print a short rationale for the template (one extra API call). |
| `--cache` | Reuse a cached response for an identical prompt instead of calling the backend. |
| `--cost` | Print token usage and an estimated USD cost for the run. |
| `--retries N` | Retry a failed MCP call up to `N` times with exponential backoff. |
| `--cve-id` / `--cwe-id` | Attach a known CVE/CWE to `info.classification`. |
| `--history` | Log this run (metadata only) to the local history database. |
| `--notify-webhook URL` | POST a summary to a Slack-compatible webhook after completion. |
| `--json` | Emit the result as JSON. |
| `--backend` / `--model` | Choose `anthropic` / `openai` and a model id. |

### Improve an existing template

```bash
mcp-nuclei improve --template existing.yaml --request original.req --output better.yaml --diff
```

`improve` supports the same `--validate`, `--verify-url`, `--verify-safe-url`, `--cache`, `--cost`, and `--retries` flags as `generate`.

### Batch a directory

```bash
mcp-nuclei batch --dir captures/ --output-dir templates/ --refine --cost --workers 4
```

`--workers N` processes captures concurrently (default 1 = sequential); results are still reported in discovery order.

### Watch a directory

```bash
mcp-nuclei watch --dir ./drop-zone --output-dir ./templates
```

Polls the directory and generates a template for each new/changed capture as it appears — handy for a live triage workflow. Ctrl+C to stop.

### Lint, dedup, and workflow

```bash
mcp-nuclei lint --template template.yaml
mcp-nuclei dedup --template template.yaml --against ~/src/nuclei-templates
mcp-nuclei workflow --template a.yaml --template b.yaml --id my-recon --name "My Recon" --output workflow.yaml
```

`dedup` never clones or fetches anything — point `--against` at a local checkout you already have.

### Eval (prompt regression testing)

```bash
mcp-nuclei eval --fixtures examples/eval
```

Replays each fixture through real generation and checks the detected vuln type, minimum matcher count, and required tags — run this after editing `prompts/*.txt` to catch regressions. See `examples/eval/*.json` for the fixture format.

### History

```bash
mcp-nuclei history --limit 20
```

Only populated for runs made with `--history`; the database never leaves your machine and only stores metadata (template id, vuln type, backend/model, token counts, cost) — never raw request/response content.

### Validate

```bash
mcp-nuclei validate --template template.yaml
```

See `--help` on any command for the full option list, and `examples/` for sample inputs, an expected-quality output, eval fixtures, and a sample config file.

## Configuration

Drop a `.mcp-nuclei.toml` in your project (or `~/.mcp-nuclei.toml`) to set defaults — CLI flags always override it. See `examples/.mcp-nuclei.toml`:

```toml
[mcp-nuclei]
author = "your-handle"
severity = "medium"
tags = "mcp-nuclei"
backend = "auto"
refine = false
auto_classify = false
```

## How it works

1. **Import** (`core/importers.py`, `core/parser.py`) — captures (raw/curl/HAR/Burp/OpenAPI) are parsed into structured request/response models.
2. **Prompt** (`prompts/*.txt`, `core/generator.py`) — a strong base system prompt (chaining + non-HTTP protocol guidance) plus a specialized prompt for the detected/forced vuln class — built-in or plugin-registered — is combined with the parsed request/response/description into a single MCP prompt.
3. **Generate** (`mcp/client.py`) — the prompt is sent to an MCP-compatible backend behind the `MCPClient` interface (Anthropic, OpenAI-compatible, or your own agent), optionally wrapped for metering (`mcp/metering.py`), retry (`mcp/retry.py`), and caching (`mcp/cache.py`).
4. **Refine** (optional) — the draft is run back through `prompts/template_improver.txt` for a critique-and-fix pass.
5. **Build & validate** (`core/builder.py`, `core/validator.py`, `core/lint.py`) — the YAML is cleaned, missing fields (including an optional CVE/CWE classification block) are filled, the structure is validated, and — if you pass `--validate`/`lint` — checked against the real `nuclei` binary / style conventions.
6. **Verify** (optional, `core/verify.py`) — with `--verify-url`/`--verify-safe-url`/`--verify-urls-file`, the template is actually run against one or more live targets via `nuclei -jsonl` to confirm the matcher fires (and doesn't fire where it shouldn't).

```
src/mcp_nuclei/
├── cli.py                # Typer CLI: generate / improve / batch / watch / lint / workflow / dedup / eval / history / validate
├── config.py             # TOML config loading
├── core/
│   ├── parser.py          # Raw HTTP text -> structured models
│   ├── importers.py       # curl / HAR / Burp XML / OpenAPI -> RequestCapture
│   ├── generator.py       # Orchestrates import -> prompt -> MCP -> build (+refine, +classify, +explain, +plugins)
│   ├── improver.py        # `improve` command logic
│   ├── batch.py           # `batch` command logic (sequential or concurrent)
│   ├── watch.py           # `watch` command logic (mtime polling)
│   ├── builder.py         # Normalizes / validates / serializes final YAML (incl. classification block)
│   ├── validator.py       # `nuclei -validate` integration (syntax)
│   ├── verify.py          # `nuclei -u <url>` integration (live matcher proof, single/negative/multi-target)
│   ├── lint.py             # nuclei-templates style/convention checks
│   ├── workflow.py         # Combine templates into a Nuclei workflow file
│   ├── dedup.py            # Local near-duplicate detection
│   ├── eval.py             # Prompt regression harness
│   ├── history.py          # Local SQLite run log
│   ├── notify.py           # Webhook notifications
│   └── plugins.py          # Third-party vuln-prompt plugin discovery
├── mcp/
│   ├── client.py           # MCPClient protocol + Anthropic & OpenAI backends
│   ├── cache.py            # Opt-in on-disk response caching
│   ├── metering.py         # Token usage accumulation across calls
│   ├── pricing.py          # Rough cost-per-token lookup table
│   └── retry.py            # Exponential-backoff retry wrapper
├── prompts/               # base (+ chaining/protocol guidance) + 11 vuln prompts + template_improver
└── utils/http.py          # Low-level raw HTTP helpers
```

### Bringing your own MCP client

The whole tool depends only on the `MCPClient` protocol in `mcp_nuclei/mcp/client.py`:

```python
class MCPClient(Protocol):
    def generate(self, *, system_prompt: str, user_prompt: str) -> str: ...
```

If you already have an MCP agent/session set up, wrap it with `CallableMCPClient`:

```python
from pathlib import Path
from mcp_nuclei.mcp.client import CallableMCPClient
from mcp_nuclei.core.generator import generate_template

client = CallableMCPClient(lambda system, user: my_agent.ask(system, user))
result = generate_template(request_path=Path("request.req"), client=client, refine=True)
print(result.template_yaml)
```

### Adding a vuln-type prompt via plugin

No fork required — register a Python entry point:

```python
# my_package/prompts.py
from pathlib import Path
from mcp_nuclei.core.plugins import PromptPlugin

def get_prompts() -> list[PromptPlugin]:
    return [
        PromptPlugin(
            vuln_type="graphql-injection",
            prompt_path=Path(__file__).parent / "graphql_injection.txt",
            keywords=("graphql injection", "graphql"),
        )
    ]
```

```toml
# my_package's pyproject.toml
[project.entry-points."mcp_nuclei.vuln_prompts"]
my_plugin = "my_package.prompts:get_prompts"
```

Once installed alongside `mcp-nuclei`, `--type graphql-injection` and description auto-detection both pick it up.

## Docker

A `Dockerfile` bundles the CLI with the real `nuclei` binary so `--validate` / `--verify-url` work out of the box:

```bash
docker build -t mcp-nuclei .
docker run --rm -e ANTHROPIC_API_KEY -v "$PWD":/work -w /work mcp-nuclei \
  generate --request examples/requests/idor-order-endpoint.req
```

## GitHub Action

`.github/workflows/generate-template.yml` is a manually-triggered (`workflow_dispatch`) action that generates a template from a capture file already in the repo and uploads it as a build artifact. It never runs automatically on push/PR, so it never spends API credits without someone explicitly dispatching it. Requires an `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) repository secret.

## Development

```bash
pip install -r requirements-dev.txt
pytest
ruff check src tests
mypy src
```

CI runs the same lint + type-check + test matrix (Python 3.10–3.12) on every push and PR. Run `mcp-nuclei eval --fixtures examples/eval` (with a backend configured) after editing any `prompts/*.txt` to catch prompt regressions.

## Roadmap

- [ ] Multipart/file-upload requests with non-text (binary) bodies; a dedicated WebSocket capture importer
- [ ] Recursive batch mode and output layout matching the nuclei-templates repo
- [ ] Live matcher verification against a target as part of `batch`
- [ ] PyPI release

## License

MIT — see [LICENSE](LICENSE).
