// dufflebag-mcp is an experimental MCP server over the dufflebag API. It is
// an ordinary API client: registry reads go through the compatibility plane,
// tenancy and operational state through the platform plane, and nothing here
// holds authority the supplied credential does not already carry.
//
// Transport is MCP stdio: newline-delimited JSON-RPC 2.0 on stdin/stdout.
//
// Configuration (environment):
//
//	DFBG_MCP_ENDPOINT        base URL, e.g. https://dufflebag.lab.orbital.home:8443
//	DFBG_MCP_CLIENT_ID       service principal client id
//	DFBG_MCP_CLIENT_SECRET   service principal client secret
//	DFBG_MCP_CA_FILE         optional PEM chain for a private CA
//	DFBG_MCP_ORGANIZATION_ID default organization for tenancy-scoped tools
//	DFBG_MCP_PROJECT_ID      default project for tenancy-scoped tools
//	DFBG_MCP_BUCKET_ID       default bucket id for bucket-taking tools; a
//	                         bucket-scoped credential defaults its own without it
//	DFBG_MCP_READ_ONLY       when truthy, mutating tools are neither listed nor callable
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

const protocolVersion = "2024-11-05"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func main() {
	log.SetOutput(os.Stderr)
	client, err := newClientFromEnv()
	if err != nil {
		log.Fatalf("dufflebag-mcp: %v", err)
	}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 16<<20)
	out := json.NewEncoder(os.Stdout)

	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("discarding unparseable frame: %v", err)
			continue
		}
		if req.ID == nil {
			// Notification: nothing to answer.
			continue
		}
		resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
		switch req.Method {
		case "initialize":
			resp.Result = map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "dufflebag-mcp", "version": "0.2.0"},
			}
		case "ping":
			resp.Result = map[string]any{}
		case "tools/list":
			resp.Result = map[string]any{"tools": toolDefinitions()}
		case "tools/call":
			result, err := callTool(client, req.Params)
			if err != nil {
				// Tool-level failures are results, not protocol errors, so the
				// model sees the message and can adjust.
				result = errorContent(err)
			}
			resp.Result = result
		default:
			resp.Error = &rpcError{Code: -32601, Message: fmt.Sprintf("method %q not found", req.Method)}
		}
		if err := out.Encode(resp); err != nil {
			log.Fatalf("write response: %v", err)
		}
	}
	if err := in.Err(); err != nil {
		log.Fatalf("read requests: %v", err)
	}
}

func errorContent(err error) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}},
		"isError": true,
	}
}
