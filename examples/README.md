# Examples

This folder contains sample request files you can use to test mcp-nuclei.

## Available Samples

- `sample-idor.req` - Example IDOR request
- `sample-sqli.req` - Example SQL Injection request

## Usage

```bash
mcp-nuclei generate --request examples/requests/sample-idor.req --output template.yaml
```