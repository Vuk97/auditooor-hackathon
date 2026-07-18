// fixture: negative - nested codec helper carries an explicit max depth bound.
package ante

import (
	"errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const MaxDecodeDepth = 8

// AnteHandle decodes the outer tx before fees and then walks nested messages.
func (d DecodeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	var raw RawTx
	if err := proto.Unmarshal(d.rawBytes, &raw); err != nil {
		return ctx, err
	}
	if err := unpackNestedMessages(raw.Body.Messages, 0); err != nil {
		return ctx, err
	}
	return next(ctx, tx, simulate)
}

// unpackNestedMessages enforces a depth cap before decoding child payloads.
func unpackNestedMessages(messages []*AnyMsg, depth int) error {
	if depth >= MaxDecodeDepth {
		return errors.New("recursion too deep")
	}
	for _, child := range messages {
		var nested NestedMsg
		if err := proto.Unmarshal(child.Value, &nested); err != nil {
			return err
		}
		if len(nested.Children) > 0 {
			if err := unpackNestedMessages(nested.Children, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
