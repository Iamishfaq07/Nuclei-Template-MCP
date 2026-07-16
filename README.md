# mcp-nuclei

**mcp-nuclei** is a powerful MCP-powered tool to generate high-quality Nuclei templates from raw HTTP requests, captured traffic, or existing templates.

It uses advanced reasoning (via MCP-compatible LLMs) to create production-ready templates instead of naive curl-to-yaml conversions.

## Features

- Generate templates from raw requests, curl, HAR, or Burp XML
- Improve existing templates with intelligent critique
- Batch processing for multiple requests
- Built-in validation using the real `nuclei` binary
- Dry-run mode to inspect prompts
- Support for multiple backends (Anthropic, OpenAI, local models)
- Self-refinement and auto-classification of vulnerability types
- Clean, modern CLI with rich output

## Installation

```bash
git clone https://github.com/Iamishfaq07/Nuclei-Template-MCP.git
cd Nuclei-Template-MCP
pip install -e .
```

## Quick Start

### Generate a template
```bash
mcp-nuclei generate --request request.req --output template.yaml
```

### Improve an existing template
```bash
mcp-nuclei improve --template old.yaml --request original.req --output improved.yaml
```

### Validate a template
```bash
mcp-nuclei validate --template template.yaml
```

### Batch processing
```bash
mcp-nuclei batch --dir ./requests/ --output-dir ./templates/
```

## Documentation

See the full documentation and advanced usage in the [docs/](docs/) folder (coming soon).

## Contributing

Contributions are welcome! Please open an issue or pull request.

## License

MIT