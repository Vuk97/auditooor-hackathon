// fixture: positive - nested codec helper recursively decodes child messages
// with no depth cap in an ante-side decode file.
package ante

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AnteHandle decodes the outer tx before fees and then walks nested messages.
func (d DecodeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	var raw RawTx
	if err := proto.Unmarshal(d.rawBytes, &raw); err != nil {
		return ctx, err
	}
	if err := unpackNestedMessages(raw.Body.Messages); err != nil {
		return ctx, err
	}
	return next(ctx, tx, simulate)
}

// unpackNestedMessages recursively unmarshals child payloads with no depth cap.
func unpackNestedMessages(messages []*AnyMsg) error {
	for _, child := range messages {
		var nested NestedMsg
		if err := proto.Unmarshal(child.Value, &nested); err != nil {
			return err
		}
		if len(nested.Children) > 0 {
			if err := unpackNestedMessages(nested.Children); err != nil {
				return err
			}
		}
	}
	return nil
}
