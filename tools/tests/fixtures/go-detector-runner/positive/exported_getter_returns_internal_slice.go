// Pattern 30 — POSITIVE fixture for
//   go.crypto.alias.exported_getter_returns_internal_slice_without_copy
//
// Mirrors Swival #023/#024/#025 cluster + Spark structural prediction
// at common/bitmap.go:33 (`Bytes() []byte { return b.value }`). Each
// exported getter returns a struct's []byte field directly, allowing
// the caller to mutate the returned slice and corrupt internal state.
package fixture

type BitMap struct {
	value []byte
	size  int
}

// BUG: returned slice aliases internal state. Caller mutation silently
// corrupts the BitMap.
func (b *BitMap) Bytes() []byte {
	return b.value
}

type Buffer struct {
	data []byte
}

// BUG: same alias-leak shape on a different struct. The caller may
// modify the returned slice and corrupt the Buffer.
func (b *Buffer) Data() []byte {
	return b.data
}

// Helper that explicitly returns a defensive copy. The DETECTOR must
// NOT fire on this method because the body invokes the copy idiom.
func (b *BitMap) BytesCopy() []byte {
	out := make([]byte, len(b.value))
	copy(out, b.value)
	return out
}
