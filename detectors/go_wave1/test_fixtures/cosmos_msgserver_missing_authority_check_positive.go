// fixture: positive — cosmos-sdk msgServer handlers missing authority checks.
// Each handler below mutates admin-gated state but never compares the
// caller-supplied authority to the module authority.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type msgServer struct {
	Keeper
}

// UpdateParams is privileged-named and reads msg.Authority but never
// validates it — any account can broadcast this and overwrite params.
func (k msgServer) UpdateParams(ctx sdk.Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	_ = msg.Authority
	k.SetParams(ctx, msg.Params)
	return &MsgUpdateParamsResponse{}, nil
}

// SetMarketConfig is privileged-named, mutates config, no authority check.
func (k msgServer) SetMarketConfig(ctx sdk.Context, msg *MsgSetMarketConfig) (*MsgSetMarketConfigResponse, error) {
	k.storeMarketConfig(ctx, msg.Config)
	return &MsgSetMarketConfigResponse{}, nil
}

// RegisterModule reads GetAuthority() but never compares it.
func (k msgServer) RegisterModule(ctx sdk.Context, msg *MsgRegisterModule) (*MsgRegisterModuleResponse, error) {
	caller := msg.GetAuthority()
	_ = caller
	k.addModule(ctx, msg.Module)
	return &MsgRegisterModuleResponse{}, nil
}
