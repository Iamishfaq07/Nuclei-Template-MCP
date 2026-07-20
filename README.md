# mcp-nuclei

A smart [Nuclei](https://github.com/projectdiscovery/nuclei) template generator that uses MCP-driven LLM reasoning to turn a captured, vulnerable HTTP request (and optional response) into a high-quality, production-ready Nuclei YAML template — not a naive curl-to-yaml conversion.

Instead of just replaying a request and matching on a status code, `mcp-nuclei` reasons about *why* the request is vulnerable and produces templates with precise matchers, sensible extractors, parameterized variables, and false-positive-aware logic — the kind of template a careful human template author would write.

## Features

- **Multiple input formats** — raw HTTP requests, `curl` commands, HAR files (browser/Charles/Fiddler), and Burp Suite XML exports, all auto-detected.
- **`generate`** — turn one capture into a high-quality template.
- **`improve`** — review and harden an existing template via MCP critique.
- **`batch`** — generate templates for a whole directory of captures at once.
- **`validate`** — run the result through the real `nuclei` binary if installed.
- **Specialized reasoning** for 11 vuln classes: IDOR, SQLi, XSS, SSRF, XXE, LFI/traversal, open redirect, SSTI, auth bypass, CORS, and command injection — auto-detected from your description, forced with `--type`, or classified by the model itself (`--auto-classify`). Includes guidance for multi-step/chained templates (login → exploit, submit → observe for stored vulns).
- **Self-critique** — `--refine` runs a second generate → critique → fix pass for tighter templates.
- **Live verification** — `--verify-url` actually runs the generated template against a real target via the `nuclei` binary and reports whether it matched, closing the gap between "the YAML is valid" and "it actually detects the bug." Opt-in only; it never fires without an explicit URL.
- **`--explain`** — a short, plain-language rationale for why the matchers prove the vulnerability, shown separately from the YAML.
- **`--diff`** on `improve` — a colored unified diff between the original and hardened template.
- **`--cache` / `--cost`** — skip re-calling the backend for an identical prompt, and see token usage + an estimated USD cost per run.
- **Pluggable backends** — Anthropic or any OpenAI-compatible endpoint (incl. local Ollama/LM Studio), or bring your own MCP agent.
- **Config file, `--dry-run`, `--json`** — sensible defaults, prompt inspection, and machine-readable output for CI pipelines.
- **Docker image** and a **GitHub Action** (`workflow_dispatch`) to generate templates in CI.

## Why not just convert curl -> yaml?

Naive converters preserve every header and cookie verbatim and match on something generic like a 200 status code, which is both fragile (breaks the moment the target changes slightly) and noisy (false-positives on unrelated pages). `mcp-nuclei` instead:

- Strips the request down to what the vulnerability actually depends on
- Picks matchers that a patched target would *not* trigger
- Adds extractors when they add real detection value
- Uses Nuclei variables (`{{BaseURL}}`, `{{Hostname}}`, `{{interactsh-url}}`, custom `{{variable}}`s) instead of hardcoding the sample target
- Chooses an honest severity based on real-world impact

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

## Usage

### Generate

From a raw HTTP request file (Burp/ZAP export), a curl command, a HAR file, or a Burp XML — the format is auto-detected:

```bash
mcp-nuclei generate --request examples/requests/idor-order-endpoint.req --output template.yaml
mcp-nuclei generate --request examples/requests/ssti-search.curl --type ssti
mcp-nuclei generate --request capture.har --output template.yaml   # uses the first request in the HAR
```

> For a HAR or Burp export containing many requests, use `batch` (below) to generate one template per request.

Give it more context — a description and the observed response — for better reasoning:

```bash
mcp-nuclei generate \
  --request examples/requests/idor-order-endpoint.req \
  --response examples/requests/idor-order-endpoint.resp \
  --description "IDOR in order endpoint - low-priv user can read other customers' orders" \
  --refine --validate \
  --output template.yaml
```

Useful flags:

| Flag | Purpose |
| --- | --- |
| `--type / -t` | Force a vuln-specific prompt (`idor`, `sqli`, `xss`, `ssrf`, `xxe`, `lfi`, `open-redirect`, `ssti`, `auth-bypass`, `cors`, `cmdi`). |
| `--format / -f` | `auto` (default), `raw`, `curl`, `har`, `burp`. |
| `--auto-classify` | Let the model classify the vuln type when you give no hint. |
| `--refine` | Second self-critique pass to harden the template. |
| `--validate` | Validate the result with the local `nuclei` binary. |
| `--dry-run` | Print the assembled MCP prompt and exit (no API call). |
| `--explain` | Print a short rationale for the template (one extra API call). |
| `--verify-url URL` | Actually run the template against `URL` via `nuclei` and report the result. **Fires real requests — only use authorized targets.** |
| `--cache` | Reuse a cached response for an identical prompt instead of calling the backend. |
| `--cost` | Print token usage and an estimated USD cost for the run. |
| `--json` | Emit the result as JSON. |
| `--backend` / `--model` | Choose `anthropic` / `openai` and a model id. |

### Improve an existing template

```bash
mcp-nuclei improve --template existing.yaml --request original.req --output better.yaml --diff
```

`improve` supports the same `--validate`, `--verify-url`, `--cache`, and `--cost` flags as `generate`.

### Batch a directory

```bash
mcp-nuclei batch --dir captures/ --output-dir templates/ --refine --cost
```

### Validate

```bash
mcp-nuclei validate --template template.yaml
```

See `--help` on any command for the full option list, and `examples/` for sample inputs, an expected-quality output, and a sample config file.

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

1. **Import** (`core/importers.py`, `core/parser.py`) — captures (raw/curl/HAR/Burp) are parsed into structured request/response models.
2. **Prompt** (`prompts/*.txt`, `core/generator.py`) — a strong base system prompt (including chained-request guidance) plus a specialized prompt for the detected/forced vuln class is combined with the parsed request/response/description into a single MCP prompt.
3. **Generate** (`mcp/client.py`) — the prompt is sent to an MCP-compatible backend behind the `MCPClient` interface (Anthropic, OpenAI-compatible, or your own agent), optionally wrapped for caching (`mcp/cache.py`) and usage metering (`mcp/metering.py`).
4. **Refine** (optional) — the draft is run back through `prompts/template_improver.txt` for a critique-and-fix pass.
5. **Build & validate** (`core/builder.py`, `core/validator.py`) — the YAML is cleaned, missing fields are filled, the structure is validated, and — if you pass `--validate` — checked against the real `nuclei` binary.
6. **Verify** (optional, `core/verify.py`) — with `--verify-url`, the template is actually run against a live target via `nuclei -jsonl` to confirm the matcher fires.

```
src/mcp_nuclei/
├── cli.py               # Typer CLI: generate / improve / batch / validate
├── config.py            # TOML config loading
├── core/
│   ├── parser.py         # Raw HTTP text -> structured models
│   ├── importers.py      # curl / HAR / Burp XML -> RequestCapture
│   ├── generator.py      # Orchestrates import -> prompt -> MCP -> build (+refine, +classify, +explain)
│   ├── improver.py       # `improve` command logic
│   ├── batch.py          # `batch` command logic
│   ├── builder.py        # Normalizes / validates / serializes final YAML
│   ├── validator.py      # `nuclei -validate` integration (syntax/lint)
│   └── verify.py         # `nuclei -u <url>` integration (live matcher proof)
├── mcp/
│   ├── client.py          # MCPClient protocol + Anthropic & OpenAI backends
│   ├── cache.py           # Opt-in on-disk response caching
│   ├── metering.py        # Token usage accumulation across calls
│   └── pricing.py         # Rough cost-per-token lookup table
├── prompts/              # base (+ chaining guidance) + 11 vuln prompts + template_improver
└── utils/http.py         # Low-level raw HTTP helpers
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

CI runs the same lint + type-check + test matrix (Python 3.10–3.12) on every push and PR.

## Roadmap

- [ ] OpenAPI / Swagger baseline template generation
- [ ] Multipart/file-upload and WebSocket request support
- [ ] Recursive batch mode and output layout matching the nuclei-templates repo
- [ ] Template deduplication against the official nuclei-templates repo
- [ ] PyPI release

## License

MIT — see [LICENSE](LICENSE).
