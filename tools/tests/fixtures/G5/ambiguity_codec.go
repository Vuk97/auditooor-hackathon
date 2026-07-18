package types

// Fixture for G5 - go.consensus.unmarshal_type_ambiguity_first_match.
// "codec" in the path satisfies the codec/consensus surface gate.

import (
	fmt "fmt"

	"github.com/gogo/protobuf/proto"
)

// AMBIGUOUS: >=2 proto.Unmarshal of the SAME buffer (any.Value) into distinct
// rival types under first-"== nil"-wins, no TypeUrl/version discriminator.
// -> MUST FIRE.
func unpackAmbiguous(any *anyMsg) (TxData, error) {
	ltx := LegacyTx{}
	if proto.Unmarshal(any.Value, &ltx) == nil {
		return &ltx, nil
	}
	atx := AccessListTx{}
	if proto.Unmarshal(any.Value, &atx) == nil {
		return &atx, nil
	}
	dtx := DynamicFeeTx{}
	if proto.Unmarshal(any.Value, &dtx) == nil {
		return &dtx, nil
	}
	return nil, fmt.Errorf("cannot unpack")
}

// DISCRIMINATED: a TypeUrl switch chooses the concrete type deterministically
// before decoding -> NOT ambiguous -> MUST STAY SILENT (FP-guard / benign).
func unpackDiscriminated(any *anyMsg) (TxData, error) {
	switch any.TypeUrl {
	case "legacy":
		ltx := LegacyTx{}
		if proto.Unmarshal(any.Value, &ltx) == nil {
			return &ltx, nil
		}
	case "accesslist":
		atx := AccessListTx{}
		if proto.Unmarshal(any.Value, &atx) == nil {
			return &atx, nil
		}
	}
	return nil, fmt.Errorf("cannot unpack")
}

// SINGLE: only one decode of the buffer -> not a type-ambiguity ladder ->
// MUST STAY SILENT (this is Pattern 28's trailing-byte lane, not G5).
func unpackSingle(any *anyMsg) (TxData, error) {
	ltx := LegacyTx{}
	if proto.Unmarshal(any.Value, &ltx) == nil {
		return &ltx, nil
	}
	return nil, fmt.Errorf("cannot unpack")
}

// DISTINCT-ARGS: two decodes but of DIFFERENT buffers -> not one-buffer
// ambiguity -> MUST STAY SILENT.
func unpackDistinctBuffers(a *anyMsg, b *anyMsg) (TxData, error) {
	ltx := LegacyTx{}
	if proto.Unmarshal(a.Value, &ltx) == nil {
		return &ltx, nil
	}
	atx := AccessListTx{}
	if proto.Unmarshal(b.Value, &atx) == nil {
		return &atx, nil
	}
	return nil, fmt.Errorf("cannot unpack")
}

type anyMsg struct {
	Value   []byte
	TypeUrl string
}

type TxData interface{ Reset() }
type LegacyTx struct{}
type AccessListTx struct{}
type DynamicFeeTx struct{}
