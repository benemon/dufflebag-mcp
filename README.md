# dufflebag-mcp

> **Independent community project.** dufflebag-mcp is not maintained,
> supported or endorsed by IBM or HashiCorp.

An experimental [Model Context Protocol](https://modelcontextprotocol.io/)
server for [dufflebag](https://github.com/benemon/dufflebag). It exposes a
registry instance to agentic clients as a set of typed tools: tenancy and
registry state, channel resolution with revocation awareness, version diffs,
ancestry freshness, vulnerability findings, ready-to-paste consumption
snippets, and gated channel promotion.

The server is an ordinary API client. It holds a service principal's
credentials, mints tokens through the instance's standard token endpoint, and
carries no authority the credential does not already hold. Transport is MCP
stdio.

Configuration, deployment, the environment reference, and the full tool
surface are documented in the
[dufflebag documentation](https://benemon.github.io/dufflebag/integrations/mcp-server).

## Build

```sh
make build
```

Or use the published container image, which shares the registry image's UBI
micro base:

```sh
docker run -i --rm \
  -e DFBG_MCP_ENDPOINT=https://dufflebag.example.com:8443 \
  -e DFBG_MCP_CLIENT_ID=... \
  -e DFBG_MCP_CLIENT_SECRET=... \
  quay.io/benjamin_holmes/dufflebag-mcp:latest
```
