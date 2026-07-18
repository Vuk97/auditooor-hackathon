// Pattern 10 — NEGATIVE fixture.
//
// Same TweakKeyShare shape, but the verifying_pubkey is recomputed via a
// proper group operation (Aggregate(...) over the new share set), so the
// aggregate invariant is preserved.
package fixturen

type ShareN struct {
	Index  uint32
	Secret []byte
}

type GroupN struct {
	Shares          []ShareN
	VerifyingPubkey []byte
}

type Point struct{ B []byte }

func (p Point) Add(o Point) Point { return Point{B: append([]byte{}, p.B...)} }

func Aggregate(shares []ShareN) []byte {
	acc := Point{}
	for _, s := range shares {
		acc = acc.Add(Point{B: s.Secret})
	}
	return acc.B
}

func TweakKeyShare(g *GroupN, idx uint32, delta []byte) error {
	g.Shares[idx].Secret = append(g.Shares[idx].Secret, delta...)
	g.VerifyingPubkey = Aggregate(g.Shares)
	return nil
}
