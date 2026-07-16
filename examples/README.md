# Examples

Sample capture files and outputs for testing mcp-nuclei.

## Requests (`requests/`)

- `sample-idor.req` — minimal IDOR request (raw HTTP)
- `sample-sqli.req` — minimal SQL injection request (raw HTTP)
- `idor-order-endpoint.req` / `.resp` — fuller IDOR request/response pair
- `ssti-search.curl` — a `curl` command (auto-detected format)

## Outputs (`outputs/`)

- `idor-order-endpoint.yaml` — an illustrative, hand-authored template showing
  the quality bar mcp-nuclei aims for.

## Config

- `.mcp-nuclei.toml` — sample config file; copy to `./.mcp-nuclei.toml` or
  `~/.mcp-nuclei.toml` to set defaults.

## Usage

```bash
mcp-nuclei generate --request examples/requests/sample-idor.req --output template.yaml
mcp-nuclei generate --request examples/requests/ssti-search.curl --type ssti
```
