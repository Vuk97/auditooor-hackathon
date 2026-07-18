// fixture: negative — handlers enforce expiry and consume the nonce.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// compares msg.Deadline against block time before acting.
func (k msgServer) ExecuteOrder(ctx sdk.Context, msg *MsgExecuteOrder) (*MsgExecuteOrderResponse, error) {
	if msg.Deadline < ctx.BlockTime().Unix() {
		return nil, ErrExpired
	}
	k.fill(ctx, msg.OrderId)
	return &MsgExecuteOrderResponse{}, nil
}

// checks and consumes the nonce to block replay.
func (k msgServer) ClaimReward(ctx sdk.Context, msg *MsgClaimReward) (*MsgClaimRewardResponse, error) {
	if k.HasNonce(ctx, msg.Nonce) {
		return nil, ErrReplay
	}
	k.ConsumeNonce(ctx, msg.Nonce)
	k.payout(ctx, msg.Claimer, msg.Amount)
	return &MsgClaimRewardResponse{}, nil
}

// handler with no expiry/nonce field — must NOT flag.
func (k msgServer) SetNickname(ctx sdk.Context, msg *MsgSetNickname) (*MsgSetNicknameResponse, error) {
	k.storeNickname(ctx, msg.Owner, msg.Nickname)
	return &MsgSetNicknameResponse{}, nil
}
