# Same runtime as the dufflebag image: UBI micro with the CA trust store
# grafted from ubi-minimal, so TLS to a registry behind a public CA works
# out of the box (a private CA is supplied via DFBG_MCP_CA_FILE). Transport
# is MCP stdio — run with an attached stdin, e.g.
# docker run -i --rm -e DFBG_MCP_ENDPOINT=... dufflebag-mcp

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /dufflebag-mcp .

FROM registry.access.redhat.com/ubi9/ubi-minimal AS trust

FROM registry.access.redhat.com/ubi9/ubi-micro
COPY --from=trust /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/tls/certs/ca-bundle.crt
COPY --from=build /dufflebag-mcp /dufflebag-mcp
USER 1001
ENTRYPOINT ["/dufflebag-mcp"]
