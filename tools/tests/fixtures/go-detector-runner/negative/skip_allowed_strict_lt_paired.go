// Pattern 40 — NEGATIVE fixture: every strict-less-than check is
// paired with an equality check or a delta-bound check. Detector
// must NOT fire.
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

// SAFE: paired with `received == g.next` to enforce strict
// monotonicity (no skip allowed).
func (g *SeqGuard) Accept(received uint64) error {
	if received < g.next {
		return fmt.Errorf("replay")
	}
	if received == g.next {
		g.next = received + 1
		return nil
	}
	return fmt.Errorf("skip not allowed")
}

// SAFE: bounded delta check `counter - expected` ensures only
// adjacent next value is accepted.
func (w *DTLSWindow) Validate(counter uint64, expected uint64) error {
	if counter < expected {
		return fmt.Errorf("rejecting replay")
	}
	if counter-expected > 1 {
		return fmt.Errorf("rejecting skip")
	}
	return nil
}

// SAFE: paired equality `seq == highest` is rejected explicitly.
func (r *ReplayGate) IsFresh(seq uint64, highest uint64) bool {
	if seq < highest {
		return false
	}
	if seq == highest {
		return false
	}
	return true
}
