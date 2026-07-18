// fixture: negative - all messages must be observer messages before bypass.
package ante

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	cctxtypes "github.com/zeta/observer/types"
)

func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	allMsgsAreObserver := true
	for _, msg := range options.Tx.GetMsgs() {
		switch msg.(type) {
		case *cctxtypes.MsgGasPriceVoter:
		case *cctxtypes.MsgVoteOnObservedInboundTx:
		default:
			allMsgsAreObserver = false
		}
	}
	if allMsgsAreObserver {
		return newCosmosAnteHandlerNoGasLimit(options), nil
	}
	return newCosmosAnteHandler(options), nil
}
