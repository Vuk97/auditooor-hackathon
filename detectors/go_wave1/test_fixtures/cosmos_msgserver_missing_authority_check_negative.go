// fixture: negative — every privileged handler validates authority, and
// ordinary user-facing handlers are correctly ignored.
package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type msgServer struct {
	Keeper
}

// UpdateParams correctly compares msg.Authority to the module authority.
func (k msgServer) UpdateParams(ctx sdk.Context, msg *MsgUpdateParams) (*MsgUpdateParamsResponse, error) {
	if msg.Authority != k.GetAuthority() {
		return nil, ErrUnauthorized
	}
	k.SetParams(ctx, msg.Params)
	return &MsgUpdateParamsResponse{}, nil
}

// SetMarketConfig validates via a helper.
func (k msgServer) SetMarketConfig(ctx sdk.Context, msg *MsgSetMarketConfig) (*MsgSetMarketConfigResponse, error) {
	if err := k.EnsureAuthority(msg.Authority); err != nil {
		return nil, err
	}
	k.storeMarketConfig(ctx, msg.Config)
	return &MsgSetMarketConfigResponse{}, nil
}

// RegisterModule compares against the gov module address.
func (k msgServer) RegisterModule(ctx sdk.Context, msg *MsgRegisterModule) (*MsgRegisterModuleResponse, error) {
	expected := authtypes.NewModuleAddress(govtypes.ModuleName).String()
	if msg.GetAuthority() != expected {
		return nil, ErrUnauthorized
	}
	k.addModule(ctx, msg.Module)
	return &MsgRegisterModuleResponse{}, nil
}

// SendCoins is a user-facing handler with no authority field — must NOT flag.
func (k msgServer) SendCoins(ctx sdk.Context, msg *MsgSend) (*MsgSendResponse, error) {
	return &MsgSendResponse{}, k.transfer(ctx, msg.From, msg.To, msg.Amount)
}

// PlaceOrder is user-facing — must NOT flag.
func (k msgServer) PlaceOrder(ctx sdk.Context, msg *MsgPlaceOrder) (*MsgPlaceOrderResponse, error) {
	return &MsgPlaceOrderResponse{}, k.book.Insert(ctx, msg.Order)
}
