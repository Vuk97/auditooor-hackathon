// Pattern 42 — POSITIVE fixture for
//   go.crypto.context_cancel.afterfunc_on_success
//
// Mirrors Swival #005 — Go context.AfterFunc registers a
// cancellation callback that runs when the context is cancelled.
// On the success path the callback should be cancelled (stop());
// without that the callback fires on a still-live resource and
// leaks the goroutine.
package fixture

import (
	"context"
	"net"
)

type Conn struct {
	c net.Conn
}

// BUG: stop handle is captured but never invoked. On success path the
// callback closes the still-live conn.
func DialAndUseAfterFuncBug(ctx context.Context, addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	_ = stop
	// SUCCESS PATH — `stop()` never called, callback stays armed.
	return &Conn{c: c}, nil
}

// BUG: handle discarded entirely with `_ =`. No way to cancel.
func DialAndDiscardAfterFunc(ctx context.Context, addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	return &Conn{c: c}, nil
}

// BUG: bare expression-statement form, no handle at all.
func DialAndBareAfterFunc(ctx context.Context, addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() {
		_ = c.Close()
	})
	return &Conn{c: c}, nil
}
