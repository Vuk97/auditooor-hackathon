// Pattern 30 — NEGATIVE fixture: every exported getter returns a
// defensive copy of the internal []byte field. Detector must NOT fire.
package fixture

import "bytes"

type BitMap struct {
	value []byte
	size  int
}

// SAFE: bytes.Clone is the idiomatic defensive copy.
func (b *BitMap) Bytes() []byte {
	return bytes.Clone(b.value)
}

type Buffer struct {
	data []byte
}

// SAFE: explicit copy idiom into a freshly-allocated slice.
func (b *Buffer) Data() []byte {
	out := make([]byte, len(b.data))
	copy(out, b.data)
	return out
}

// SAFE: append-into-fresh-slice idiom.
func (b *Buffer) DataAppended() []byte {
	return append([]byte{}, b.data...)
}

// Non-getter exported method — different return type, irrelevant to
// the detector.
func (b *BitMap) Size() int {
	return b.size
}

// Method that takes a parameter — out of scope (zero-arg getter shape
// is the bug class).
func (b *BitMap) Slice(n int) []byte {
	return b.value[:n]
}
