// fixture: positive — handlers read expiry/nonce but never enforce it.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// reads msg.Deadline but never compares it to block time.
func (k msgServer) ExecuteOrder(ctx sdk.Context, msg *MsgExecuteOrder) (*MsgExecuteOrderResponse, error) {
	_ = msg.Deadline
	k.fill(ctx, msg.OrderId)
	return &MsgExecuteOrderResponse{}, nil
}

// reads msg.Nonce but never marks it consumed.
func (k msgServer) ClaimReward(ctx sdk.Context, msg *MsgClaimReward) (*MsgClaimRewardResponse, error) {
	id := msg.Nonce
	_ = id
	k.payout(ctx, msg.Claimer, msg.Amount)
	return &MsgClaimRewardResponse{}, nil
}
