// fixture: negative — decoders bound payload size / depth before unmarshal.
package ante

import (
	"encoding/json"
	"errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const MaxTxBytes = 1 << 20

// AnteHandle rejects oversized payloads before decoding.
func (d DecodeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if len(d.rawBytes) > MaxTxBytes {
		return ctx, errors.New("tx too large")
	}
	var inner InnerTx
	if err := proto.Unmarshal(d.rawBytes, &inner); err != nil {
		return ctx, err
	}
	return next(ctx, tx, simulate)
}

// decodeMsg checks max depth before unmarshalling.
func decodeMsg(bz []byte, depth int) (*NestedMsg, error) {
	if depth > MaxDecodeDepth {
		return nil, errors.New("recursion too deep")
	}
	var m NestedMsg
	if err := json.Unmarshal(bz, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// a non-decoder handler — must NOT flag even though it has no bound.
func (k Keeper) PlaceOrder(ctx sdk.Context, msg *MsgPlaceOrder) error {
	return k.book.Insert(ctx, msg.Order)
}
