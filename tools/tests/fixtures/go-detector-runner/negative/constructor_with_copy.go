// Pattern 27 — NEGATIVE fixture: constructor performs a defensive copy
// of the caller-supplied []byte before storing it. Detector must NOT
// fire.
package fixture

import "bytes"

type BitMap struct {
	value []byte
	size  int
}

// SAFE: explicit `copy` of caller bytes into a freshly-allocated slice.
func NewBitMapFromBytesSafe(b []byte, size int) *BitMap {
	buf := make([]byte, len(b))
	copy(buf, b)
	return &BitMap{value: buf, size: size}
}

// SAFE: bytes.Clone is the idiomatic defensive copy.
func NewBufferCloned(payload []byte) *BitMap {
	return &BitMap{value: bytes.Clone(payload), size: len(payload)}
}

// SAFE: append-into-fresh-slice idiom.
func NewBufferAppended(payload []byte) *BitMap {
	return &BitMap{value: append([]byte{}, payload...), size: len(payload)}
}

// Constructor without a []byte param — irrelevant to this detector,
// must not fire.
func NewBitMap(size int) *BitMap {
	return &BitMap{value: make([]byte, (size+7)/8), size: size}
}
