// Pattern 7 — POSITIVE fixture for
//   go.bitcoin.byte_reversed_lookup_set
//
// Function reverses a txHash (slices.Reverse) and inserts BOTH the
// original and reversed values into the same lookup set. Doubles the
// pre-image space an attacker can hit. (watch_chain.go:894-925 shape.)
package fixture

import "slices"

type Watcher struct {
	known map[string]struct{}
}

func (w *Watcher) Track(txHash []byte) {
	rev := make([]byte, len(txHash))
	copy(rev, txHash)
	slices.Reverse(rev)
	w.known[string(txHash)] = struct{}{}
	w.known[string(rev)] = struct{}{}
}
