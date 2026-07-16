# mcp-nuclei

A smart [Nuclei](https://github.com/projectdiscovery/nuclei) template generator that uses MCP-driven LLM reasoning to turn a captured, vulnerable HTTP request (and optional response) into a high-quality, production-ready Nuclei YAML template — not a naive curl-to-yaml conversion.

Instead of just replaying a request and matching on a status code, `mcp-nuclei` reasons about *why* the request is vulnerable and produces templates with precise matchers, sensible extractors, parameterized variables, and false-positive-aware logic — the kind of template a careful human template author would write.

## Why not just convert curl -> yaml?

Naive converters preserve every header and cookie verbatim and match on something generic like a 200 status code, which is both fragile (breaks the moment the target changes slightly) and noisy (false-positives on unrelated pages). `mcp-nuclei` instead:

- Strips the request down to what the vulnerability actually depends on
- Picks matchers that a patched target would *not* trigger
- Adds extractors when they add real detection value
- Uses Nuclei variables (`{{BaseURL}}`, `{{Hostname}}`, custom `{{variable}}`s) instead of hardcoding the sample target
- Chooses an honest severity based on real-world impact

## Installation

```bash
git clone https://github.com/Iamishfaq07/Nuclei-Template-MCP.git
cd Nuclei-Template-MCP
pip install -e .
```

To use the built-in Anthropic-backed MCP client, install the optional `llm` extra and set an API key:

```bash
pip install -e ".[llm]"
export ANTHROPIC_API_KEY="sk-ant-..."
```

For development (tests, linting, type checking):

```bash
pip install -r requirements-dev.txt
```

## Usage

Generate a template from a raw HTTP request file (e.g. exported from Burp Suite or ZAP):

```bash
mcp-nuclei generate --request examples/requests/idor-order-endpoint.req --output template.yaml
```

Give it more context — a description and the observed response — for better reasoning:

```bash
mcp-nuclei generate \
  --request examples/requests/idor-order-endpoint.req \
  --response examples/requests/idor-order-endpoint.resp \
  --description "IDOR in order endpoint - low-priv user can read other customers' orders" \
  --output template.yaml
```

Force a specific vulnerability-type prompt instead of relying on auto-detection:

```bash
mcp-nuclei generate --request request.req --type sqli --severity high --tags sqli,mysql
```

Print to stdout instead of writing a file (the default when `--output` is omitted):

```bash
mcp-nuclei generate --request request.req
```

See `--help` for the full list of options:

```bash
mcp-nuclei generate --help
```

See `examples/requests/` for sample input files and `examples/outputs/` for the quality bar `mcp-nuclei` aims for.

## How it works

1. **Parse** (`core/parser.py`) — the raw HTTP request/response files are parsed into structured models.
2. **Prompt** (`prompts/*.txt`, `core/generator.py`) — a strong base system prompt (plus a specialized prompt for IDOR/SQLi/XSS when detected or forced via `--type`) is combined with the parsed request/response/description into a single MCP prompt.
3. **Generate** (`mcp/client.py`) — the prompt is sent to an MCP-compatible backend behind the `MCPClient` interface. A ready-to-use `AnthropicMCPClient` is included; swap in your own agent/session by implementing the same interface.
4. **Build & validate** (`core/builder.py`) — the model's YAML output is cleaned (markdown fences stripped), missing fields are filled with sane defaults, and the result is validated before being written out.

```
src/mcp_nuclei/
├── cli.py              # Typer CLI entry point
├── core/
│   ├── parser.py        # Raw HTTP request/response -> structured models
│   ├── generator.py      # Orchestrates parsing -> prompting -> MCP -> building
│   └── builder.py        # Normalizes/validates/serializes the final YAML
├── mcp/
│   └── client.py         # MCPClient interface + Anthropic-backed implementation
├── prompts/
│   ├── base.txt
│   ├── idor.txt
│   ├── sqli.txt
│   ├── xss.txt
│   └── template_improver.txt
└── utils/
    └── http.py            # Low-level raw HTTP text helpers
```

### Bringing your own MCP client

The whole tool depends only on the `MCPClient` protocol in `mcp_nuclei/mcp/client.py`:

```python
class MCPClient(Protocol):
    def generate(self, *, system_prompt: str, user_prompt: str) -> str: ...
```

If you already have an MCP agent/session set up, wrap it with `CallableMCPClient`:

```python
from mcp_nuclei.mcp.client import CallableMCPClient
from mcp_nuclei.core.generator import generate_template

client = CallableMCPClient(lambda system, user: my_agent.ask(system, user))
result = generate_template(request_path=Path("request.req"), client=client)
print(result.template_yaml)
```

## Development

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
mypy src
```

## Roadmap

- [ ] `improve` command using `prompts/template_improver.txt` to iterate on an existing template
- [ ] Burp XML import
- [ ] Batch mode (generate templates for a directory of captured requests)
- [ ] Optional local template validation via the `nuclei` binary itself

## License

MIT — see [LICENSE](LICENSE).
