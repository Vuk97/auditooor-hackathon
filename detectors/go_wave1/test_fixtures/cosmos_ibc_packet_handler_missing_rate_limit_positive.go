// fixture: positive — IBC handlers move funds with no rate-limit guard.
package ibcmodule

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	channeltypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
)

// OnRecvPacket credits the recipient directly, no quota check.
func (im IBCModule) OnRecvPacket(ctx sdk.Context, packet channeltypes.Packet, relayer sdk.AccAddress) error {
	data := decodeTransfer(packet.GetData())
	return im.bankKeeper.SendCoinsFromModuleToAccount(ctx, "transfer", data.Receiver, data.Amount)
}

// OnTimeoutPacket refunds escrow with no flow-control check.
func (im IBCModule) OnTimeoutPacket(ctx sdk.Context, packet channeltypes.Packet, relayer sdk.AccAddress) error {
	data := decodeTransfer(packet.GetData())
	return im.bankKeeper.SendCoins(ctx, im.escrow, data.Sender, data.Amount)
}
