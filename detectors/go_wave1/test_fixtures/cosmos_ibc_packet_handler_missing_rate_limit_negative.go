// fixture: negative — IBC handlers route fund moves through rate-limit guard.
package ibcmodule

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	channeltypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
)

// OnRecvPacket checks the rate-limit flow before crediting.
func (im IBCModule) OnRecvPacket(ctx sdk.Context, packet channeltypes.Packet, relayer sdk.AccAddress) error {
	data := decodeTransfer(packet.GetData())
	if err := im.rateLimitKeeper.CheckRateLimitAndUpdateFlow(ctx, RECV, data); err != nil {
		return err
	}
	return im.bankKeeper.SendCoinsFromModuleToAccount(ctx, "transfer", data.Receiver, data.Amount)
}

// OnTimeoutPacket undoes the recorded flow before refunding escrow.
func (im IBCModule) OnTimeoutPacket(ctx sdk.Context, packet channeltypes.Packet, relayer sdk.AccAddress) error {
	data := decodeTransfer(packet.GetData())
	im.rateLimitKeeper.UndoSend(ctx, data)
	return im.bankKeeper.SendCoins(ctx, im.escrow, data.Sender, data.Amount)
}

// OnAcknowledgementPacket does no fund move — must NOT flag.
func (im IBCModule) OnAcknowledgementPacket(ctx sdk.Context, packet channeltypes.Packet, ack []byte, relayer sdk.AccAddress) error {
	im.logAck(ctx, packet, ack)
	return nil
}
