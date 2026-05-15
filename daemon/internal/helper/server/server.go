// Package server implements the helper's unix-socket listener. The
// socket lives at /run/host-health-mcp/helper.sock with mode 0660,
// owned root:<daemon-group>. The helper chowns both the socket and
// its parent runtime directory at bind time so the daemon (which
// runs as an unprivileged user) can traverse the dir and connect to
// the socket. SO_PEERCRED then verifies the connecting peer's uid
// matches the daemon's (design §6.7).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

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
	// SocketGID is the group the socket and its parent directory are
	// chowned to after bind so the daemon can traverse and connect.
	// Zero leaves ownership as root:root (used in tests).
	SocketGID uint32
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
	// systemd's RuntimeDirectory= creates /run/host-health-mcp/ as
	// root:root because the helper unit runs as root:root. The
	// daemon (an unprivileged user) cannot traverse a root:root 0750
	// directory. Chown the parent and the socket itself to the
	// daemon's primary group so it can connect. Requires CAP_CHOWN
	// in the helper unit's bounding set; the shipped base unit
	// keeps CAP_CHOWN even when manifest-derived caps would
	// otherwise be empty.
	if s.cfg.SocketGID != 0 {
		parent := filepath.Dir(s.cfg.SocketPath)
		if err := os.Chown(parent, 0, int(s.cfg.SocketGID)); err != nil {
			ln.Close()
			return fmt.Errorf("server: chown runtime dir %s: %w", parent, err)
		}
		if err := os.Chown(s.cfg.SocketPath, 0, int(s.cfg.SocketGID)); err != nil {
			ln.Close()
			return fmt.Errorf("server: chown socket: %w", err)
		}
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

// idleTimeout bounds how long the helper will wait for the next
// request frame on an established connection. Defence-in-depth
// against a daemon-side fd leak or partial-write attacker holding
// open a helper goroutine indefinitely.
const idleTimeout = 60 * time.Second

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	defer s.untrack(c)

	if !s.checkPeer(c) {
		return
	}

	for {
		_ = c.SetReadDeadline(time.Now().Add(idleTimeout))
		var req proto.Request
		if err := proto.ReadFrame(c, &req); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})

		resp := s.dispatch(ctx, &req)

		_ = c.SetWriteDeadline(time.Now().Add(idleTimeout))
		if err := proto.WriteFrameWithCap(c, resp, proto.MaxResponseFrame); err != nil {
			return
		}
		_ = c.SetWriteDeadline(time.Time{})
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
		return errResp(proto.CodeBadOp, "unknown op token")
	}
	h, ok := s.cfg.Registry.Lookup(req.Op)
	if !ok {
		return errResp(proto.CodeBadOp, "op not compiled into this helper")
	}

	result, err := h(ctx, req.Param)
	if err != nil {
		var de *dispatch.Error
		if errors.As(err, &de) {
			return errRespFromDispatch(de)
		}
		return errResp(proto.CodeInternal, err.Error())
	}

	body, mErr := json.Marshal(result)
	if mErr != nil {
		return errResp(proto.CodeInternal, "result marshal: "+mErr.Error())
	}
	return &proto.Response{Status: proto.StatusOK, Data: body}
}

func errResp(code, msg string) *proto.Response {
	return &proto.Response{
		Status:  proto.StatusErr,
		Code:    code,
		Message: msg,
	}
}

func errRespFromDispatch(de *dispatch.Error) *proto.Response {
	return &proto.Response{
		Status:       proto.StatusErr,
		Code:         de.Code,
		Message:      de.Message,
		StderrBytes:  de.StderrBytes,
		StderrSHA256: de.StderrSHA256,
		StderrPrefix: de.StderrPrefix,
		ToolExit:     de.ToolExit,
		Argv:         de.Argv,
	}
}
