// Fixture: cometbft-style message that lacks ValidateBasic input
// sanitisation on a public ingress path. Mirrors several
// cometbft-cometbft-ghsa-* records in the cosmos_sdk_ibc corpus tag
// where unconstrained-length / nil-deref / negative-index input was
// accepted by the verifier and propagated to consensus.
//
// Detector w22_go_cometbft_validate_basic should fire on this file.
package types

import (
	"errors"
)

// MsgRelayCommit is a stand-in for any cometbft / cosmos-sdk message
// type. Positive shape: ValidateBasic is declared on the value
// receiver, but the body returns nil unconditionally -- no length /
// nil / range checks on the embedded slices. CWE-20.
type MsgRelayCommit struct {
	Height   int64
	Round    int32
	Voters   [][]byte
	Sigs     [][]byte
	Metadata []byte
}

// Positive: ValidateBasic does not validate Voters length, Sigs length,
// or the bound between Voters and Sigs; an attacker can submit
// len(Voters)=0 or len(Sigs)!=len(Voters) and crash the downstream
// verifier with index-out-of-range or nil deref.
func (m MsgRelayCommit) ValidateBasic() error {
	_ = m
	return nil
}

// Stub for the upstream verify path that will panic if MsgRelayCommit
// is not sanitised. Included so the negative fixture has a target.
func VerifyRelayCommit(m MsgRelayCommit) error {
	if m.Height < 0 {
		return errors.New("height negative")
	}
	for i := range m.Voters {
		_ = m.Sigs[i] // panics if len(Sigs) < len(Voters).
	}
	return nil
}
