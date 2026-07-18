package keeper

type Context struct{}

type Params struct{}
type MarketConfig struct{}
type ModuleConfig struct{}
type Profile struct{}

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

type MsgUpdateProfile struct {
	Owner   string
	Profile Profile
}

type Account struct {
	Owner string
}

type Keeper struct {
	authority string
}

func (k Keeper) GetAuthority() string { return k.authority }
func (k Keeper) SetParams(ctx Context, params Params) {}
func (k Keeper) storeMarketConfig(ctx Context, cfg MarketConfig) {}
func (k Keeper) addModule(ctx Context, module ModuleConfig) {}
func (k Keeper) SetProfile(ctx Context, owner string, profile Profile) {}
func (k Keeper) GetAccount(ctx Context, owner string) Account { return Account{Owner: owner} }
func (k Keeper) AssertAuthority(ctx Context, admin string) error { return nil }

type msgServer struct {
	Keeper
}

func (m msgServer) UpdateParams(ctx Context, msg *MsgUpdateParams) error {
	if msg.Authority != m.Keeper.GetAuthority() {
		return ErrUnauthorized
	}
	m.Keeper.SetParams(ctx, msg.Params)
	return nil
}

func (m msgServer) SetMarketConfig(ctx Context, msg *MsgSetMarketConfig) error {
	if err := m.Keeper.AssertAuthority(ctx, msg.Admin); err != nil {
		return err
	}
	m.Keeper.storeMarketConfig(ctx, msg.Config)
	return nil
}

func (k Keeper) RegisterModule(ctx Context, msg *MsgRegisterModule) error {
	gov := authtypes.NewModuleAddress(govtypes.ModuleName)
	if msg.Owner != gov.String() {
		return ErrUnauthorized
	}
	k.addModule(ctx, msg.Module)
	return nil
}

func (m msgServer) UpdateProfile(ctx Context, msg *MsgUpdateProfile) error {
	account := m.Keeper.GetAccount(ctx, msg.Owner)
	if account.Owner != msg.Owner {
		return ErrUnauthorized
	}
	m.Keeper.SetProfile(ctx, msg.Owner, msg.Profile)
	return nil
}
