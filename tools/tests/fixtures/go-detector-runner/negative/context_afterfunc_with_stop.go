// Pattern 42 — NEGATIVE fixture: every context.AfterFunc call has
// a captured stop handle that is invoked (defer / direct call) on
// the success path. Detector must NOT fire.
package fixture

import (
	"context"
	"net"
)

type Conn struct {
	c net.Conn
}

// SAFE: defer stop() ensures the AfterFunc is cancelled regardless
// of return path.
func DialAndDeferStop(ctx context.Context, addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	defer stop()
	return &Conn{c: c}, nil
}

// SAFE: explicit stop() called on the success path.
func DialAndExplicitStop(ctx context.Context, addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	if c != nil {
		stop()
	}
	return &Conn{c: c}, nil
}

// SAFE: distinct name `cancel` — still defended via defer.
func DialAndDeferCancel(ctx context.Context, addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	cancel := context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	defer cancel()
	return &Conn{c: c}, nil
}
