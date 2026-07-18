// fixture: negative - guards bind transfer decisions to IBC scope.
package ibcmodule

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	channeltypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
	transfertypes "github.com/cosmos/ibc-go/v8/modules/apps/transfer/types"
)

// OnRecvPacket scopes quota by channel, denom, and sender before crediting.
func (im IBCModule) OnRecvPacket(ctx sdk.Context, packet channeltypes.Packet, relayer sdk.AccAddress) error {
	data := decodeTransfer(packet.GetData())
	scope := RateScope{
		Channel: packet.GetSourceChannel(),
		Denom:   data.Denom,
		Sender:  data.Sender,
	}
	if err := im.rateLimitKeeper.CheckQuota(ctx, scope, data.Amount); err != nil {
		return err
	}
	return im.bankKeeper.SendCoinsFromModuleToAccount(ctx, "transfer", data.Receiver, data.Amount)
}

// SendTransfer checks sender, receiver, channel, and denom in one blocklist call.
func (k Keeper) SendTransfer(ctx sdk.Context, msg *transfertypes.MsgTransfer) error {
	if k.blocklist.IsBlocked(ctx, msg.SourceChannel, msg.Token.Denom, msg.Sender, msg.Receiver) {
		return ErrBlockedTransfer
	}
	return k.transferKeeper.Transfer(ctx, msg)
}
