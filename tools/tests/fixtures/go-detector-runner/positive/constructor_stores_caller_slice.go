// Pattern 27 — POSITIVE fixture for
//   go.crypto.alias.constructor_stores_caller_slice_without_copy
//
// Mirrors Swival #023/#024/#025 + Spark structural hit at
// spark/common/bitmap.go:12. The constructor stores the caller-supplied
// []byte verbatim in a struct field; no defensive copy is performed.
package fixture

type BitMap struct {
	value []byte
	size  int
}

// BUG: caller-controlled slice stored verbatim. Mutation in the caller
// silently mutates this BitMap's internal state.
func NewBitMapFromBytes(bytes []byte, size int) *BitMap {
	return &BitMap{value: bytes, size: size}
}

// Second positive shape — different field name, different struct, same
// caller-aliasing pitfall. Both should fire.
type Buffer struct {
	data []byte
}

func NewBuffer(payload []byte) *Buffer {
	return &Buffer{data: payload}
}
