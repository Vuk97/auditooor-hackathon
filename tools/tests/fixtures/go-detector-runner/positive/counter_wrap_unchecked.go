// Pattern 37 — POSITIVE fixture for
//   go.crypto.counter.wrap_unchecked
//
// Mirrors Swival #009 / #044 — counter wrap collisions on per-message
// sequence numbers (gossip replay) or per-block AES-GCM nonces.
package fixture

import (
	"sync/atomic"
)

type SeqCounter struct {
	seqNum uint64
}

type GossipState struct {
	next  uint64
	mutex int
}

type NonceHolder struct {
	nonce uint64
}

// BUG: `seqNum++` in a hot path without an `^uint64(0)` / `math.MaxUint64`
// overflow guard. Wrap allows replay.
func (c *SeqCounter) Next() uint64 {
	c.seqNum++
	return c.seqNum
}

// BUG: `next += 1` in a loop body without a wrap guard.
func (g *GossipState) AdvanceN(n int) {
	for i := 0; i < n; i++ {
		g.next += 1
	}
}

// BUG: atomic counter increment without an overflow guard.
func (n *NonceHolder) NextNonce() uint64 {
	return atomic.AddUint64(&n.nonce, 1)
}
