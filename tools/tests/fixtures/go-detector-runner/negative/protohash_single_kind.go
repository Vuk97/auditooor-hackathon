// Pattern 5 — NEGATIVE fixture.
//
// Same protohash.Hash call, but only ONE kind-identifier helper is used
// over a given argument. No collision risk under field-kind drift.
package fixturen

type FDN struct {
	Number int32
}

func intIdentifier(fd FDN) []byte { return []byte("i") }

type protoHashN struct{}

func (protoHashN) Hash(b []byte) []byte { return b }

var protohash = protoHashN{}

func HashFieldSafe(fd FDN) []byte {
	a := intIdentifier(fd)
	return protohash.Hash(a)
}
