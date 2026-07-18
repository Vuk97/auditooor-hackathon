// Pattern 40 — POSITIVE fixture for
//   go.crypto.skip_allowed.strict_lt_only
//
// Mirrors Swival #032 / #033 — sequence-number guards rejecting only
// replays via strict ``<`` without rejecting jumps via ``==`` pair.
package fixture

import "fmt"

type SeqGuard struct {
	next uint64
}

type DTLSWindow struct {
	counter uint64
}

type ReplayGate struct {
	seq uint64
}

// BUG: only `received < g.next` rejects replays; never checks
// `received == g.next` or a delta-bound. An attacker can submit
// `received = g.next + 1000`, the guard accepts, and `g.next` is
// updated, skipping the 999 intermediate sequence numbers. Future
// legitimate values 1..999 are now rejected as replay.
func (g *SeqGuard) Accept(received uint64) error {
	if received < g.next {
		return fmt.Errorf("replay: received=%d next=%d", received, g.next)
	}
	g.next = received + 1
	return nil
}

// BUG: only `counter < expected` rejects replays. Same monotonic-skip
// shape as above, just under a different name.
func (w *DTLSWindow) Validate(counter uint64, expected uint64) error {
	if counter < expected {
		return fmt.Errorf("rejecting replay")
	}
	return nil
}

// BUG: only `seq < highest` rejects replays. No delta-bound check.
func (r *ReplayGate) IsFresh(seq uint64, highest uint64) bool {
	if seq < highest {
		return false
	}
	return true
}
