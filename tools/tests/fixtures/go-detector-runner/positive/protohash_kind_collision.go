// Pattern 5 — POSITIVE fixture for
//   go.protohash.kind_identifier_collision
//
// Body funnels the same descriptor field through both intIdentifier and
// uintIdentifier, then routes the result through protohash.Hash. A silent
// proto kind change (int32 -> uint32) under the same field number then
// collides because both helpers map to the same canonical bytes.
package fixture

type FieldDescriptor struct {
	Number int32
	Kind   string
}

func intIdentifier(fd FieldDescriptor) []byte  { return []byte("i") }
func uintIdentifier(fd FieldDescriptor) []byte { return []byte("i") }

type protoHash struct{}

func (protoHash) Hash(b []byte) []byte { return b }

var protohash = protoHash{}

func HashField(fd FieldDescriptor) []byte {
	a := intIdentifier(fd)
	b := uintIdentifier(fd)
	_ = b
	return protohash.Hash(a)
}
