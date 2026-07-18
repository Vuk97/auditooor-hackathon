// fixture: positive - IBC quota and blocklist guards omit transfer scope.
package ibcmodule

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	channeltypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
	transfertypes "github.com/cosmos/ibc-go/v8/modules/apps/transfer/types"
)

// OnRecvPacket checks only amount, so another channel or denom trace bypasses quota.
func (im IBCModule) OnRecvPacket(ctx sdk.Context, packet channeltypes.Packet, relayer sdk.AccAddress) error {
	data := decodeTransfer(packet.GetData())
	if err := im.rateLimitKeeper.CheckQuota(ctx, data.Amount); err != nil {
		return err
	}
	return im.bankKeeper.SendCoinsFromModuleToAccount(ctx, "transfer", data.Receiver, data.Amount)
}

// SendTransfer blocks only the receiver, not the sender and IBC denom/channel tuple.
func (k Keeper) SendTransfer(ctx sdk.Context, msg *transfertypes.MsgTransfer) error {
	if k.blocklist.IsBlockedAddr(msg.Receiver) {
		return ErrBlockedAddress
	}
	return k.transferKeeper.Transfer(ctx, msg)
}
