// fixture: positive — ante-side decoders unmarshal with no size/depth bound.
package ante

import (
	"encoding/json"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// AnteHandle fully unmarshals raw tx bytes with no size guard.
func (d DecodeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	var inner InnerTx
	if err := proto.Unmarshal(d.rawBytes, &inner); err != nil {
		return ctx, err
	}
	return next(ctx, tx, simulate)
}

// decodeMsg unmarshals a nested msg with no depth cap.
func decodeMsg(bz []byte) (*NestedMsg, error) {
	var m NestedMsg
	if err := json.Unmarshal(bz, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
