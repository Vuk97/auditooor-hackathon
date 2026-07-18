// Pattern 10 — POSITIVE fixture for
//   go.frost.aggregate_pubkey_invariant_violation
//
// TweakKeyShare rotates a participant share AND overwrites the
// aggregate verifying_pubkey with a constructor-style assignment, but
// never recomputes it via .Add(/.Sub(/Aggregate(. Any signature already
// witnessed against the old aggregate verifying_pubkey is now orphaned.
package fixture

type Share struct {
	Index  uint32
	Secret []byte
}

type Group struct {
	Shares          []Share
	VerifyingPubkey []byte
}

func deriveBytesFromShare(s Share) []byte { return append([]byte{}, s.Secret...) }

func TweakKeyShare(g *Group, idx uint32, delta []byte) error {
	g.Shares[idx].Secret = append(g.Shares[idx].Secret, delta...)
	// Bug: replace verifying_pubkey from a fresh derivation that doesn't
	// preserve the aggregate invariant. No .Add(/.Sub(/Aggregate(/Recompute.
	g.VerifyingPubkey = deriveBytesFromShare(g.Shares[idx])
	return nil
}
