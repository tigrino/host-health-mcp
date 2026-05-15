// Package mcp implements the MCP server side of the plugin over
// newline-delimited JSON-RPC 2.0 on stdio. One MCP tool per daemon
// RPC; tool names are namespaced under a configurable prefix. Tool
// descriptors carry a JSON-Schema inputSchema declaring the per-call
// `host` argument (REQ 7.2).
//
// Methods implemented:
//   - initialize                 lifecycle handshake
//   - notifications/initialized  client-side completion notify
//   - ping                       keepalive
//   - tools/list                 declare tools and their schemas
//   - tools/call                 invoke one tool against one host
//
// Notifications (no `id` field) never produce a response, per
// JSON-RPC 2.0 §4.1.
//
// On first contact with a host per session, the plugin compares its
// compiled SchemaVersion against the daemon's `schema_version` from
// the manifest envelope (version-matrix C1-C4). A major-version
// mismatch marks the host incompatible for the lifetime of the
// process; subsequent tool calls to that host return
// `schema_incompatible` without a network round-trip.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"host-health-mcp/plugin/internal/client"
	pluginschema "host-health-mcp/plugin/internal/schema"
)

// protocolVersion is the MCP spec date the server advertises.
// "2024-11-05" is the first stable published revision.
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
	defaultHost string
	serverName  string
	version     string

	writeMu sync.Mutex

	// Per-host compatibility cache. Populated lazily on the first
	// tool call per host per process lifetime (version-matrix §2).
	compatMu sync.Mutex
	compat   map[string]hostCompat
}

// hostCompat is the cached compatibility classification for one host.
type hostCompat struct {
	ok     bool   // true for C1/C2/C3, false for C4
	reason string // populated when !ok; surfaced in the error message
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
		compat:      make(map[string]hostCompat),
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
		isNotification := len(req.ID) == 0 || string(req.ID) == "null"
		resp, suppress := s.dispatch(ctx, &req)
		if isNotification || suppress {
			continue
		}
		s.write(w, resp)
	}
	return scanner.Err()
}

// dispatch returns the response plus a suppress flag (true for
// methods that have no response by design, like
// notifications/initialized).
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

type callContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

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

	// Schema-version gate. The manifest tool itself is the probe and
	// must always be reachable (version-matrix C4); every other tool
	// is short-circuited when the host is known-incompatible.
	if found.DaemonRPC != "manifest" {
		if hc, ok := s.cachedCompat(resolved); ok && !hc.ok {
			return s.toolError(req.ID, "schema_incompatible: "+hc.reason)
		}
		if !s.hasCompat(resolved) {
			if err := s.probeCompat(ctx, resolved); err != nil {
				return s.toolError(req.ID, "schema probe: "+err.Error())
			}
			if hc, _ := s.cachedCompat(resolved); !hc.ok {
				return s.toolError(req.ID, "schema_incompatible: "+hc.reason)
			}
		}
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

	// On a successful manifest call, opportunistically populate the
	// compat cache so a later non-manifest call doesn't have to
	// probe.
	if found.DaemonRPC == "manifest" && !s.hasCompat(resolved) {
		s.recordCompatFromEnvelope(resolved, raw)
	}

	return jsonRPCResult(req.ID, callResult{
		Content: []callContent{{Type: "text", Text: string(raw)}},
	})
}

func (s *Server) toolError(id json.RawMessage, msg string) jsonRPCResponse {
	return jsonRPCResult(id, callResult{
		Content: []callContent{{Type: "text", Text: msg}},
		IsError: true,
	})
}

// hasCompat reports whether a compat decision has been cached for
// the host already.
func (s *Server) hasCompat(host string) bool {
	s.compatMu.Lock()
	defer s.compatMu.Unlock()
	_, ok := s.compat[host]
	return ok
}

func (s *Server) cachedCompat(host string) (hostCompat, bool) {
	s.compatMu.Lock()
	defer s.compatMu.Unlock()
	hc, ok := s.compat[host]
	return hc, ok
}

func (s *Server) storeCompat(host string, hc hostCompat) {
	s.compatMu.Lock()
	defer s.compatMu.Unlock()
	s.compat[host] = hc
}

// probeCompat calls /v1/manifest against host and classifies the
// daemon's schema_version against the plugin's compiled view.
func (s *Server) probeCompat(ctx context.Context, host string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, errResp, err := s.cli.Call(probeCtx, host, "manifest", []byte("{}"))
	if err != nil {
		return err
	}
	if errResp != nil {
		return fmt.Errorf("%s", errResp.String())
	}
	s.recordCompatFromEnvelope(host, raw)
	return nil
}

// recordCompatFromEnvelope extracts schema_version from a manifest
// envelope and writes the classification into the cache.
func (s *Server) recordCompatFromEnvelope(host string, raw []byte) {
	var env struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.SchemaVersion == "" {
		s.storeCompat(host, hostCompat{ok: false, reason: "daemon manifest missing schema_version"})
		return
	}
	pluginMajor, _ := parseMajor(pluginschema.SchemaVersion)
	daemonMajor, ok := parseMajor(env.SchemaVersion)
	if !ok {
		s.storeCompat(host, hostCompat{
			ok:     false,
			reason: "unparseable daemon schema_version " + env.SchemaVersion,
		})
		return
	}
	if pluginMajor != daemonMajor {
		s.storeCompat(host, hostCompat{
			ok: false,
			reason: fmt.Sprintf("plugin schema %s incompatible with daemon schema %s (major mismatch)",
				pluginschema.SchemaVersion, env.SchemaVersion),
		})
		return
	}
	s.storeCompat(host, hostCompat{ok: true})
}

// parseMajor returns the major-version integer of a "M.m.p" semver.
// Returns ok=false on any parse failure.
func parseMajor(semver string) (int, bool) {
	dot := strings.IndexByte(semver, '.')
	if dot <= 0 {
		return 0, false
	}
	n, err := strconv.Atoi(semver[:dot])
	if err != nil {
		return 0, false
	}
	return n, true
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
