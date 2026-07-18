// Pattern 7 — NEGATIVE fixture.
//
// Reverses txHash but only inserts ONE canonical orientation into the set
// (the canonical big-endian form). No pre-image expansion, no finding.
package fixturen

import "slices"

type WatcherN struct {
	known map[string]struct{}
}

func (w *WatcherN) Track(txHash []byte) {
	rev := make([]byte, len(txHash))
	copy(rev, txHash)
	slices.Reverse(rev)
	// Only the canonical (reversed-to-display) orientation is stored.
	w.known[string(rev)] = struct{}{}
}
