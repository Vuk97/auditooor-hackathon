// Pattern 33 — NEGATIVE fixture: each parsed integer is followed by a
// lower-bound guard on the same destination identifier. Detector must
// NOT fire.
package fixture

import (
	"fmt"
	"strconv"
)

type cbString struct{}

func (s *cbString) ReadASN1Int64() (int64, bool) { return 0, true }
func (s *cbString) ReadInt32() (int32, bool)     { return 0, true }

// SAFE: explicit `requireExplicitPolicy < 0` rejection guard.
func ParsePolicyConstraintsGuarded(s *cbString) (int64, error) {
	requireExplicitPolicy, _ := s.ReadASN1Int64()
	if requireExplicitPolicy < 0 {
		return 0, fmt.Errorf("requireExplicitPolicy must be non-negative")
	}
	return requireExplicitPolicy + 1, nil
}

// SAFE: positive-form `iter > 0` precondition.
func ParseIterCountGuarded(in string) ([]byte, error) {
	iter, err := strconv.ParseInt(in, 10, 32)
	if err != nil {
		return nil, err
	}
	if iter <= 0 {
		return nil, fmt.Errorf("iter must be positive")
	}
	out := []byte{}
	for j := int64(0); j < iter; j++ {
		out = append(out, byte(j))
	}
	return out, nil
}

// SAFE: `opcode == 0` sentinel branch handles the zero case.
func ReadOpcodeGuarded(s *cbString) int32 {
	opcode, _ := s.ReadInt32()
	if opcode == 0 {
		return -1
	}
	return opcode
}
