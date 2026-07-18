// Fixture: hypothetical cosmos-sdk app that DOES wire IBC Hooks middleware.
// Used by tools/tests/test_d6_cve_middleware.py to verify Stage 2
// reachability=open detection for ibc-hooks-receive class advisories.
package app

import (
	ibchookskeeper "github.com/cosmos/ibc-apps/modules/ibc-hooks/v8/keeper"
	ibckeeper "github.com/cosmos/ibc-go/v8/modules/core/keeper"
	icahostkeeper "github.com/cosmos/ibc-go/v8/modules/apps/27-interchain-accounts/host/keeper"
)

type App struct {
	IBCKeeper       *ibckeeper.Keeper
	IBCHooksKeeper  ibchookskeeper.Keeper
	ICAHostKeeper   icahostkeeper.Keeper
}

func newApp() *App {
	a := &App{}
	a.IBCKeeper = ibckeeper.NewKeeper(/* args elided */)
	a.IBCHooksKeeper = ibchookskeeper.NewKeeper(/* args elided */)
	a.ICAHostKeeper = icahostkeeper.NewKeeper(/* args elided */)
	return a
}
