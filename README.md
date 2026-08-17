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

## Configuration

| Variable | Description |
| --- | --- |
| `DFBG_MCP_ENDPOINT` | Dufflebag base URL. |
| `DFBG_MCP_CLIENT_ID` | Service principal client id. |
| `DFBG_MCP_CLIENT_SECRET` | Service principal client secret. |
| `DFBG_MCP_CA_FILE` | Optional PEM chain for a private CA. |
| `DFBG_MCP_ORGANIZATION_ID` | Optional default organization for tenancy-scoped tools. |
| `DFBG_MCP_PROJECT_ID` | Optional default project for tenancy-scoped tools. |
| `DFBG_MCP_BUCKET_ID` | Optional default bucket id for bucket-scoped tools. |
| `DFBG_MCP_READ_ONLY` | When true, mutating tools are neither listed nor callable. |

Bucket-scoped service principals use the existing client id and secret
variables. Set `DFBG_MCP_BUCKET_ID` to the bucket's ULID (its id, not its
name) so bucket-taking tools can omit their bucket argument.

## Compatibility

The server is version-tolerant rather than version-coupled: most tools speak
dufflebag's frozen HCP-compatibility plane, and features that touch native
surfaces degrade when the server predates them. The table states the floor per
feature; everything else works against any dufflebag release.

| Feature | Needs dufflebag | Below that |
| --- | --- | --- |
| `find_artifact` via the search endpoint | ≥ 0.1.0 | Falls back to enumeration. |
| Declared bucket scoping (`DFBG_MCP_BUCKET_ID`) | ≥ 0.1.0 | Credentials still confine server-side where enforced; the declared default and fail-fast check need the scoped listing. |

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
