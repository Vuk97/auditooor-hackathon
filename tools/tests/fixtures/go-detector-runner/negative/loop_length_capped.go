// Pattern 36 — NEGATIVE fixture: every parsed length-prefix is
// capped against an explicit upper bound BEFORE driving a loop.
// Detector must NOT fire.
package fixture

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type cbString struct{}

func (s *cbString) ReadASN1Int64() (int64, bool) { return 0, true }

const maxLen = 1024

// SAFE: explicit `length > maxLen` cap before the loop.
func ParseTLVCapped(s *cbString) ([]byte, error) {
	length, _ := s.ReadASN1Int64()
	if length > maxLen {
		return nil, fmt.Errorf("length %d exceeds max %d", length, maxLen)
	}
	out := []byte{}
	for i := int64(0); i < length; i++ {
		out = append(out, byte(i))
	}
	return out, nil
}

// SAFE: parsed length is capped against a documented upper bound
// before the countdown loop runs.
func ConsumeBytesCapped(in string) (string, error) {
	length, err := strconv.ParseUint(in, 10, 32)
	if err != nil {
		return "", err
	}
	if length >= maxLen {
		return "", fmt.Errorf("length too large")
	}
	acc := ""
	for length > 0 {
		acc += "."
		length -= 1
	}
	return acc, nil
}

// SAFE: parsed count is capped against a static maximum.
func ReadFieldsCapped(buf []byte) ([][]byte, error) {
	count := binary.BigEndian.Uint32(buf)
	if count >= maxLen {
		return nil, fmt.Errorf("count too large")
	}
	out := make([][]byte, 0)
	for i := uint32(0); i < count; i++ {
		out = append(out, []byte{})
	}
	return out, nil
}
