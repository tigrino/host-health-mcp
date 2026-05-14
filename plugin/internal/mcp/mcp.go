// Package mcp implements the MCP server side of the plugin over
// newline-delimited JSON-RPC 2.0 on stdio. One MCP tool per daemon
// RPC; tool names are namespaced under a configurable prefix
// (default "host_"). Tool descriptors carry a JSON-Schema inputSchema
// declaring the per-call `host` argument (REQ 7.2).
//
// Methods implemented:
//   - initialize                 lifecycle handshake
//   - notifications/initialized  client-side completion notify
//   - ping                       keepalive
//   - tools/list                 declare tools and their schemas
//   - tools/call                 invoke one tool against one host
//
// Notifications (no `id` field) never produce a response, per
// JSON-RPC 2.0.
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

// protocolVersion is the MCP spec date the server advertises. The
// client may negotiate a different version; this is just our
// preferred. "2024-11-05" is the first stable published revision.
const protocolVersion = "2024-11-05"

// Tool is one MCP-exposed tool, backed by one daemon RPC.
type Tool struct {
	Name        string // user-visible MCP tool name (prefix+rpc)
	DaemonRPC   string // the daemon's /v1/<rpc> endpoint
	Description string
	TimeoutS    int
}

// Server runs over stdio.
type Server struct {
	cli         *client.Client
	tools       []Tool
	defaultHost string // HOSTHEALTH_TARGET_HOST; "" means none
	serverName  string
	version     string

	writeMu sync.Mutex
}

// New constructs a Server. defaultHost is used when a tools/call
// omits the `host` argument; empty disables the default.
func New(cli *client.Client, tools []Tool, defaultHost, serverName, version string) *Server {
	return &Server{
		cli:         cli,
		tools:       tools,
		defaultHost: defaultHost,
		serverName:  serverName,
		version:     version,
	}
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
		// Notification: no id, no response (JSON-RPC 2.0 §4.1).
		isNotification := len(req.ID) == 0 || string(req.ID) == "null"
		resp, suppress := s.dispatch(ctx, &req)
		if isNotification || suppress {
			continue
		}
		s.write(w, resp)
	}
	return scanner.Err()
}

// dispatch returns the response plus a suppress flag (true if the
// method has no response by design, like notifications/initialized).
func (s *Server) dispatch(ctx context.Context, req *jsonRPCRequest) (jsonRPCResponse, bool) {
	switch req.Method {
	case "initialize":
		return jsonRPCResult(req.ID, s.initialize()), false
	case "notifications/initialized":
		return jsonRPCResponse{}, true
	case "ping":
		return jsonRPCResult(req.ID, map[string]any{}), false
	case "tools/list":
		return jsonRPCResult(req.ID, s.list()), false
	case "tools/call":
		return s.call(ctx, req), false
	default:
		return jsonRPCError(req.ID, -32601, "method not found: "+req.Method), false
	}
}

// initialize response shape per MCP spec.
type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ServerInfo      serverInfo     `json:"serverInfo"`
	Capabilities    map[string]any `json:"capabilities"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (s *Server) initialize() initializeResult {
	return initializeResult{
		ProtocolVersion: protocolVersion,
		ServerInfo:      serverInfo{Name: s.serverName, Version: s.version},
		Capabilities: map[string]any{
			"tools": map[string]any{},
		},
	}
}

// toolDescriptor is the MCP-spec shape returned by tools/list.
type toolDescriptor struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func (s *Server) list() any {
	out := make([]toolDescriptor, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, toolDescriptor{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: s.inputSchema(),
		})
	}
	return map[string]any{"tools": out}
}

// inputSchema returns the JSON-Schema for every tool. The schema is
// the same across tools because the daemon's wire surface takes an
// empty body; the only argument the plugin layer needs is `host`.
func (s *Server) inputSchema() map[string]any {
	hostDesc := "Target host. Optional if the plugin has HOSTHEALTH_TARGET_HOST set."
	if s.defaultHost != "" {
		hostDesc += fmt.Sprintf(" Default: %q.", s.defaultHost)
	}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"host": map[string]any{
				"type":        "string",
				"description": hostDesc,
			},
		},
		"additionalProperties": false,
	}
}

// callContent is one entry in the MCP tools/call content array.
type callContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// callResult is the MCP shape returned by tools/call.
type callResult struct {
	Content []callContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

func (s *Server) call(ctx context.Context, req *jsonRPCRequest) jsonRPCResponse {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCError(req.ID, -32602, "bad params: "+err.Error())
	}
	var found *Tool
	for i := range s.tools {
		if s.tools[i].Name == params.Name {
			found = &s.tools[i]
			break
		}
	}
	if found == nil {
		return jsonRPCError(req.ID, -32602, "unknown tool: "+params.Name)
	}

	host, _ := params.Arguments["host"].(string)
	if host == "" {
		host = s.defaultHost
	}
	if host == "" {
		return s.toolError(req.ID, "host argument is required (no HOSTHEALTH_TARGET_HOST default configured)")
	}
	resolved, err := s.cli.ResolveHost(host)
	if err != nil {
		return s.toolError(req.ID, err.Error())
	}

	timeout := time.Duration(found.TimeoutS) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	raw, errResp, err := s.cli.Call(callCtx, resolved, found.DaemonRPC, []byte("{}"))
	if err != nil {
		return s.toolError(req.ID, "transport: "+err.Error())
	}
	if errResp != nil {
		return s.toolError(req.ID, errResp.String())
	}

	// Surface the daemon's envelope as a single text content item.
	// The model can parse the JSON itself if it needs to discriminate
	// data vs. warnings.
	return jsonRPCResult(req.ID, callResult{
		Content: []callContent{{Type: "text", Text: string(raw)}},
	})
}

func (s *Server) toolError(id json.RawMessage, msg string) jsonRPCResponse {
	// Per MCP spec, tool execution errors are surfaced via a normal
	// result with isError=true, not a JSON-RPC error. Protocol errors
	// (bad params, unknown method, etc.) still use jsonRPCError.
	return jsonRPCResult(id, callResult{
		Content: []callContent{{Type: "text", Text: msg}},
		IsError: true,
	})
}

func (s *Server) write(w io.Writer, resp jsonRPCResponse) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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
