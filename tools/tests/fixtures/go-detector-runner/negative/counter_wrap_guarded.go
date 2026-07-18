// Pattern 37 — NEGATIVE fixture: every counter increment is paired
// with an explicit overflow guard or a Reset/Rotate/Rekey call.
// Detector must NOT fire.
package fixture

import (
	"fmt"
	"math"
)

type SeqCounter struct {
	seqNum uint64
}

type GossipState struct {
	next uint64
}

type NonceHolder struct {
	nonce uint64
}

// SAFE: explicit `math.MaxUint64` overflow guard before increment.
func (c *SeqCounter) Next() (uint64, error) {
	if c.seqNum == math.MaxUint64 {
		return 0, fmt.Errorf("seq overflow")
	}
	c.seqNum++
	return c.seqNum, nil
}

// SAFE: counter wrapped via modulus reset.
func (g *GossipState) AdvanceModulus(n int) {
	for i := 0; i < n; i++ {
		g.next = g.next % 65535
		g.next += 1
	}
}

// SAFE: increment paired with a Rekey() invocation as the documented
// wrap renewal mechanism.
func (n *NonceHolder) NextNonce() uint64 {
	if n.nonce == ^uint64(0) {
		n.Rekey()
	}
	n.nonce++
	return n.nonce
}

func (n *NonceHolder) Rekey() {
	n.nonce = 0
}
