// fixture: positive - any observer Msg selects the no-gas ante path.
package ante

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	cctxtypes "github.com/zeta/observer/types"
)

func NewAnteHandler(options HandlerOptions) (sdk.AnteHandler, error) {
	anteHandler := newCosmosAnteHandler(options)
	for _, msg := range options.Tx.GetMsgs() {
		switch msg.(type) {
		case *cctxtypes.MsgGasPriceVoter:
			anteHandler = newCosmosAnteHandlerNoGasLimit(options)
		case *cctxtypes.MsgVoteOnObservedInboundTx:
			anteHandler = newCosmosAnteHandlerNoGasLimit(options)
		}
	}
	return anteHandler, nil
}
