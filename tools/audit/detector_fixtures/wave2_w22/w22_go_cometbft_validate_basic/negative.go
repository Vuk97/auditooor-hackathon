// Fixture: cometbft-style message WITH ValidateBasic input sanitisation
// on the public ingress path. Structurally similar to positive.go but
// should NOT fire the w22_go_cometbft_validate_basic detector.
package types

import (
	"errors"
	"fmt"
)

type MsgRelayCommit struct {
	Height   int64
	Round    int32
	Voters   [][]byte
	Sigs     [][]byte
	Metadata []byte
}

const (
	maxVoters       = 10_000
	maxMetadataSize = 1 << 20
)

// Negative: ValidateBasic asserts every public-input invariant the
// downstream verifier depends on (non-negative height, non-empty
// voter set, voters-sigs cardinality, metadata bound, no nil entries).
func (m MsgRelayCommit) ValidateBasic() error {
	if m.Height < 0 {
		return errors.New("height negative")
	}
	if m.Round < 0 {
		return errors.New("round negative")
	}
	if len(m.Voters) == 0 {
		return errors.New("voters empty")
	}
	if len(m.Voters) > maxVoters {
		return fmt.Errorf("voters exceed cap %d", maxVoters)
	}
	if len(m.Voters) != len(m.Sigs) {
		return errors.New("voters/sigs cardinality mismatch")
	}
	for i, v := range m.Voters {
		if len(v) == 0 {
			return fmt.Errorf("voter %d empty", i)
		}
		if len(m.Sigs[i]) == 0 {
			return fmt.Errorf("sig %d empty", i)
		}
	}
	if len(m.Metadata) > maxMetadataSize {
		return errors.New("metadata too large")
	}
	return nil
}

func VerifyRelayCommit(m MsgRelayCommit) error {
	if err := m.ValidateBasic(); err != nil {
		return err
	}
	for i := range m.Voters {
		_ = m.Sigs[i]
	}
	return nil
}
