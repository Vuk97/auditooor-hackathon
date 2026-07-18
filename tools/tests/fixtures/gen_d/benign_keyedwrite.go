package keeper

import abci "x/abci"

func (k Keeper) EndBlocker(ctx Context) []abci.ValidatorUpdate {
	powers := make(map[string]int64)
	byOwner := make(map[string][]abci.ValidatorUpdate)
	for addr := range powers {
		byOwner[addr] = append(byOwner[addr], abci.ValidatorUpdate{Addr: addr})
	}
	return byOwner["x"]
}
