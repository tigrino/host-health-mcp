// Package mcp implements the MCP server side of the plugin. One MCP
// tool per daemon RPC; tool names are namespaced under a configurable
// prefix (default "host_"). Tool descriptions in the MCP manifest
// declare read-only nature and the timeout (REQ 7.2).
//
// This is the skeleton: it implements enough of the MCP wire protocol
// over stdio to register tools, handle list/call requests, and emit
// envelope-aware responses. A production deployment would lean on a
// proper MCP SDK; keeping it stdlib-only here avoids pinning a
// pre-1.0 dependency in the review-gate skeleton.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"tigr.net/host-health-mcp/plugin/internal/client"
)

// Tool is one MCP-exposed tool, backed by one daemon RPC.
type Tool struct {
	Name        string // user-visible MCP tool name (prefix+rpc)
	DaemonRPC   string // the daemon's /v1/<rpc> endpoint
	Description string
	TimeoutS    int
}

// Server runs over stdio. It reads newline-delimited JSON requests on
// stdin and writes responses on stdout. This is the loosest viable
// MCP framing and is sufficient for the skeleton; a real deployment
// substitutes the framing the MCP SDK requires.
type Server struct {
	cli   *client.Client
	tools []Tool

	mu sync.Mutex
}

// New constructs a Server.
func New(cli *client.Client, tools []Tool) *Server {
	return &Server{cli: cli, tools: tools}
}

// Serve runs the read-dispatch loop until ctx is cancelled or stdin
// closes.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(w, jsonRPCError(nil, -32700, "parse error"))
			continue
		}
		resp := s.dispatch(ctx, &req)
		s.write(w, resp)
	}
	return scanner.Err()
}

func (s *Server) dispatch(ctx context.Context, req *jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "tools/list":
		return jsonRPCResult(req.ID, s.list())
	case "tools/call":
		return s.call(ctx, req)
	default:
		return jsonRPCError(req.ID, -32601, "method not found: "+req.Method)
	}
}

type toolDescriptor struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	TimeoutS    int    `json:"timeout_s"`
	ReadOnly    bool   `json:"read_only"`
}

func (s *Server) list() any {
	out := make([]toolDescriptor, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, toolDescriptor{
			Name:        t.Name,
			Description: t.Description,
			TimeoutS:    t.TimeoutS,
			ReadOnly:    true,
		})
	}
	return map[string]any{"tools": out}
}

func (s *Server) call(ctx context.Context, req *jsonRPCRequest) jsonRPCResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCError(req.ID, -32602, "bad params")
	}
	var found *Tool
	for i := range s.tools {
		if s.tools[i].Name == params.Name {
			found = &s.tools[i]
			break
		}
	}
	if found == nil {
		return jsonRPCError(req.ID, -32601, "unknown tool: "+params.Name)
	}

	timeout := time.Duration(found.TimeoutS) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body := params.Arguments
	if len(body) == 0 {
		body = []byte("{}")
	}

	raw, errResp, err := s.cli.Call(callCtx, found.DaemonRPC, body)
	if err != nil {
		return jsonRPCError(req.ID, -32000, "daemon call failed: "+err.Error())
	}
	if errResp != nil {
		return jsonRPCError(req.ID, -32000, errResp.String())
	}
	// The daemon returns a schema.Envelope; pass through to the caller
	// as the tool's result. The plugin surfaces warnings[] without
	// flattening them into data (REQ 7.2).
	var env map[string]any
	if jerr := json.Unmarshal(raw, &env); jerr != nil {
		return jsonRPCError(req.ID, -32603, "envelope parse: "+jerr.Error())
	}
	return jsonRPCResult(req.ID, env)
}

func (s *Server) write(w io.Writer, resp jsonRPCResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp: marshal response: %v\n", err)
		return
	}
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

// jsonRPCRequest is the minimal subset of JSON-RPC 2.0 used here.
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func jsonRPCResult(id json.RawMessage, result any) jsonRPCResponse {
	return jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func jsonRPCError(id json.RawMessage, code int, msg string) jsonRPCResponse {
	return jsonRPCResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
