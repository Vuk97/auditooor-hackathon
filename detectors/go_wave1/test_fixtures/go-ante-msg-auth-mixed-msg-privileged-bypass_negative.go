// fixture: negative - the bypass is selected only when every Msg qualifies.
package ante

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	cctxtypes "github.com/zeta/observer/types"
)

func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	allObserverMsgs := true
	for _, msg := range options.Tx.GetMsgs() {
		switch msg.(type) {
		case *cctxtypes.MsgGasPriceVoter:
			continue
		case *cctxtypes.MsgVoteOnObservedInboundTx:
			continue
		default:
			allObserverMsgs = false
		}
	}
	if allObserverMsgs {
		return newCosmosAnteHandlerNoGasLimit(options), nil
	}
	return newCosmosAnteHandler(options), nil
}
