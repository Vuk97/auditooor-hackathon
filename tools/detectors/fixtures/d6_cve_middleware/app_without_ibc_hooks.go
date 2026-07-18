// Fixture: hypothetical cosmos-sdk app that does NOT wire IBC Hooks or
// CosmWasm. Mirrors the dydx v4-chain audit-pin shape: IBC + ICAHost are
// wired, but ibc-hooks and wasmd are absent. Used by D6 tests to verify
// reachability=blocked-by-middleware for ibc-hooks-receive and
// cosmwasm-execute classes.
package app

import (
	ibckeeper "github.com/cosmos/ibc-go/v8/modules/core/keeper"
	icahostkeeper "github.com/cosmos/ibc-go/v8/modules/apps/27-interchain-accounts/host/keeper"
)

type App struct {
	IBCKeeper     *ibckeeper.Keeper
	ICAHostKeeper icahostkeeper.Keeper
	// Note: no IBCHooksKeeper, no WasmKeeper, no PacketForwardKeeper.
	// A casual reader might guess from this comment that ibc-hooks could
	// be wired, but the comment is stripped by _strip_noise() so it must
	// not cause a false positive.
}

func newApp() *App {
	a := &App{}
	a.IBCKeeper = ibckeeper.NewKeeper(/* args elided */)
	a.ICAHostKeeper = icahostkeeper.NewKeeper(/* args elided */)
	return a
}
