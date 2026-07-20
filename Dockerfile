# Build: docker build -t mcp-nuclei .
# Run:   docker run --rm -e ANTHROPIC_API_KEY -v "$PWD":/work -w /work mcp-nuclei \
#          generate --request examples/requests/idor-order-endpoint.req
#
# Includes the real `nuclei` binary so --validate / --verify-url work out of
# the box inside the container.
FROM python:3.12-slim AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install the nuclei binary (pinned version) so `--validate` / `--verify-url` work.
ARG NUCLEI_VERSION=3.3.2
RUN curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir ".[llm,openai]"

WORKDIR /work
ENTRYPOINT ["mcp-nuclei"]
CMD ["--help"]
