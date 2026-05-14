// Package server implements the helper's unix-socket listener. The
// socket lives at /run/host-health-mcp/helper.sock with mode 0660,
// owned by root:host-health-mcp. The helper verifies via SO_PEERCRED
// that connecting peers belong to the daemon's uid before accepting
// any frame (design §6.7).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"tigr.net/host-health-mcp/daemon/internal/helper/dispatch"
	"tigr.net/host-health-mcp/daemon/internal/shared/proto"
)

// Config configures a Server.
type Config struct {
	// SocketPath is the absolute path of the unix socket the helper
	// listens on.
	SocketPath string
	// AllowedUID is the only uid permitted to connect. SO_PEERCRED is
	// consulted on every accept.
	AllowedUID uint32
	// SocketMode is the file mode applied to the socket after bind.
	SocketMode os.FileMode
	// Registry is the dispatch table.
	Registry *dispatch.Registry
}

// Server accepts daemon connections on a unix socket and routes each
// request frame to the registered handler.
type Server struct {
	cfg Config
	ln  net.Listener

	mu   sync.Mutex
	open map[net.Conn]struct{}
}

// New constructs a Server. It does not listen yet; call Serve.
func New(cfg Config) *Server {
	return &Server{cfg: cfg, open: make(map[net.Conn]struct{})}
}

// Serve binds the unix socket and runs the accept loop until ctx is
// cancelled. The socket is removed before bind if a stale file is
// present and re-removed on shutdown.
func (s *Server) Serve(ctx context.Context) error {
	if err := os.Remove(s.cfg.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("server: stale socket remove: %w", err)
	}
	ln, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("server: listen: %w", err)
	}
	if err := os.Chmod(s.cfg.SocketPath, s.cfg.SocketMode); err != nil {
		ln.Close()
		return fmt.Errorf("server: chmod socket: %w", err)
	}
	s.ln = ln

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.closeAll()
				return ctx.Err()
			}
			return fmt.Errorf("server: accept: %w", err)
		}
		s.track(conn)
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.open[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.open, c)
	s.mu.Unlock()
}

func (s *Server) closeAll() {
	s.mu.Lock()
	for c := range s.open {
		c.Close()
	}
	s.open = make(map[net.Conn]struct{})
	s.mu.Unlock()
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	defer s.untrack(c)

	if !s.checkPeer(c) {
		return
	}

	for {
		var req proto.Request
		if err := proto.ReadFrame(c, &req); err != nil {
			return
		}

		resp := s.dispatch(ctx, &req)

		if err := proto.WriteFrame(c, resp); err != nil {
			return
		}
	}
}

func (s *Server) checkPeer(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var ucred *syscall.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		ucred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || sockErr != nil || ucred == nil {
		return false
	}
	return ucred.Uid == s.cfg.AllowedUID
}

func (s *Server) dispatch(ctx context.Context, req *proto.Request) *proto.Response {
	if !proto.IsKnownOp(req.Op) {
		return errResp(proto.CodeBadOp, "unknown op token", 0, "", nil)
	}
	h, ok := s.cfg.Registry.Lookup(req.Op)
	if !ok {
		return errResp(proto.CodeBadOp, "op not compiled into this helper", 0, "", nil)
	}

	result, err := h(ctx, req.Param)
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) {
			return errResp(de.Code, de.Message, de.StderrBytes, de.StderrSHA256, de.ToolExit)
		}
		return errResp(proto.CodeInternal, err.Error(), 0, "", nil)
	}

	body, mErr := json.Marshal(result)
	if mErr != nil {
		return errResp(proto.CodeInternal, "result marshal: "+mErr.Error(), 0, "", nil)
	}
	return &proto.Response{Status: proto.StatusOK, Data: body}
}

func errResp(code, msg string, stderrBytes int, stderrSHA string, toolExit *int) *proto.Response {
	return &proto.Response{
		Status:       proto.StatusErr,
		Code:         code,
		Message:      msg,
		StderrBytes:  stderrBytes,
		StderrSHA256: stderrSHA,
		ToolExit:     toolExit,
	}
}
