package keeper

type Context struct{}

type Params struct{}
type MarketConfig struct{}
type ModuleConfig struct{}
type OracleConfig struct{}

type MsgUpdateParams struct {
	Authority string
	Params    Params
}

type MsgSetMarketConfig struct {
	Admin  string
	Config MarketConfig
}

type MsgRegisterModule struct {
	Owner  string
	Module ModuleConfig
}

func (m MsgRegisterModule) GetSigner() string {
	return m.Owner
}

type MsgSetOracleOwner struct {
	Signer string
	Oracle OracleConfig
}

type Keeper struct{}

func (k Keeper) SetParams(ctx Context, params Params) {}
func (k Keeper) storeMarketConfig(ctx Context, cfg MarketConfig) {}
func (k Keeper) addModule(ctx Context, module ModuleConfig) {}
func (k Keeper) storeOracleOwner(ctx Context, signer string, oracle OracleConfig) {}
func (k Keeper) GetAuthority() string { return "gov" }

type msgServer struct {
	Keeper
}

func (m msgServer) UpdateParams(ctx Context, msg *MsgUpdateParams) error {
	authority := msg.Authority
	_ = authority
	m.Keeper.SetParams(ctx, msg.Params)
	return nil
}

func (m msgServer) SetMarketConfig(ctx Context, msg *MsgSetMarketConfig) error {
	if msg.Admin == "" {
		return ErrInvalid
	}
	m.Keeper.storeMarketConfig(ctx, msg.Config)
	return nil
}

func (k Keeper) RegisterModule(ctx Context, msg *MsgRegisterModule) error {
	signer := msg.GetSigner()
	_ = signer
	k.addModule(ctx, msg.Module)
	return nil
}

func (m msgServer) SetOracleOwner(ctx Context, msg *MsgSetOracleOwner) error {
	m.Keeper.storeOracleOwner(ctx, msg.Signer, msg.Oracle)
	if msg.Signer != m.Keeper.GetAuthority() {
		return ErrUnauthorized
	}
	return nil
}
