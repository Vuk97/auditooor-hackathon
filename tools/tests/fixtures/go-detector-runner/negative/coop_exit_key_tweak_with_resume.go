// Pattern 14 — NEGATIVE fixture.
//
// Post-SP-2988 fixed shape: tweakKeysForCoopExitFixed iterates transfer
// leaves AND mutates per-leaf state, but the loop body opens with the
// canonical resumability guard:
//
//     if leaf.KeyTweak == nil {
//         continue
//     }
//
// (and a second variant with len() == 0 for SP-2988 v1 / 9e06adf shape).
// Pattern 14 must NOT fire on this body.
package fixturen14

import (
	"context"
	"fmt"
)

type leafRowN struct {
	KeyTweak []byte
	Status   string
}

type entUpdateN struct{}

func (e *entUpdateN) ClearKeyTweak() *entUpdateN              { return e }
func (e *entUpdateN) SetStatus(s string) *entUpdateN          { return e }
func (e *entUpdateN) Save(ctx context.Context) (*leafRowN, error) { return nil, nil }

func (l *leafRowN) Update() *entUpdateN { return &entUpdateN{} }

type transferRowN struct{}

func (t *transferRowN) QueryTransferLeaves() *transferQueryN { return &transferQueryN{} }

type transferQueryN struct{}

func (q *transferQueryN) All(ctx context.Context) ([]*leafRowN, error) {
	return nil, nil
}

// Fixed: in-loop continue keyed off the cleared KeyTweak sentinel field.
func tweakKeysForCoopExitFixed(ctx context.Context, transfer *transferRowN) error {
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return fmt.Errorf("failed to query CoopExit transfer leaves: %w", err)
	}
	for _, leaf := range transferLeaves {
		if leaf.KeyTweak == nil {
			// A prior block's run of this loop already tweaked this leaf
			// and cleared the field but bailed before processing the rest.
			// Skip so subsequent leaves can be tweaked one-per-block.
			continue
		}
		_, err := leaf.Update().ClearKeyTweak().Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to clear KeyTweak: %w", err)
		}
	}
	return nil
}

// Also fixed via the SP-2988 v1 shape (commit 9e06adf): len(field) == 0 skip.
func tweakKeysForCoopExitFixedV1(ctx context.Context, transfer *transferRowN) error {
	transferLeaves, err := transfer.QueryTransferLeaves().All(ctx)
	if err != nil {
		return fmt.Errorf("CoopExit query failed: %w", err)
	}
	for _, leaf := range transferLeaves {
		if len(leaf.KeyTweak) == 0 {
			continue
		}
		_, err := leaf.Update().ClearKeyTweak().Save(ctx)
		if err != nil {
			return fmt.Errorf("KeyTweak clear failed: %w", err)
		}
	}
	return nil
}
