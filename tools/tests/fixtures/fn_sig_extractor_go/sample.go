package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/dydxprotocol/v4-chain/protocol/x/affiliates/types"
)

// msgServer is the keeper-backed message server.
type msgServer struct {
	k Keeper
}

// RegisterAffiliate accepts ANY Bech32-decodable address — NO BlockedAddr / authority check.
func (k msgServer) RegisterAffiliate(ctx context.Context, msg *types.MsgRegisterAffiliate) (*types.MsgRegisterAffiliateResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	addr, err := sdk.AccAddressFromBech32(msg.Affiliate)
	if err != nil {
		return nil, err
	}
	k.k.SetAffiliate(sdkCtx, msg.Referee, addr)
	return &types.MsgRegisterAffiliateResponse{}, nil
}

// UpdateAffiliateTiers HAS the authority check (sibling-protected).
func (k msgServer) UpdateAffiliateTiers(ctx context.Context, msg *types.MsgUpdateAffiliateTiers) (*types.MsgUpdateAffiliateTiersResponse, error) {
	if msg.Authority != k.k.GetAuthority() {
		return nil, fmt.Errorf("unauthorized")
	}
	if err := k.k.SetTiers(ctx, msg.Tiers); err != nil {
		return nil, err
	}
	return &types.MsgUpdateAffiliateTiersResponse{}, nil
}

// unexportedHelper is package-private.
func unexportedHelper(x int) int {
	return x * 2
}

// MultiReturn shows multi-return parsing.
func (k *Keeper) MultiReturn(ctx sdk.Context) (uint64, string, error) {
	return 0, "", nil
}
