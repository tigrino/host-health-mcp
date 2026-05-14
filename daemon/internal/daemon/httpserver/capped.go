package httpserver

import (
	"net"
	"sync"
)

// cappedListener limits in-flight TLS handshakes. New connections above
// the cap are accepted and immediately closed; this drops the caller
// before TLS handshake CPU is spent.
type cappedListener struct {
	net.Listener
	sem chan struct{}

	mu     sync.Mutex
	closed bool
}

func newCappedListener(inner net.Listener, cap int) *cappedListener {
	return &cappedListener{Listener: inner, sem: make(chan struct{}, cap)}
}

func (l *cappedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	select {
	case l.sem <- struct{}{}:
		return &cappedConn{Conn: c, sem: l.sem}, nil
	default:
		c.Close()
		// Continue accepting; loop until we get an admittable conn.
		return l.Accept()
	}
}

func (l *cappedListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()
	return l.Listener.Close()
}

type cappedConn struct {
	net.Conn
	sem  chan struct{}
	once sync.Once
}

func (c *cappedConn) Close() error {
	c.once.Do(func() { <-c.sem })
	return c.Conn.Close()
}
