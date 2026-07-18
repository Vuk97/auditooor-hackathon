package keeper

import (
	"sort"
	abci "x/abci"
)

func (k Keeper) EndBlocker(ctx Context) []abci.ValidatorUpdate {
	powers := make(map[string]int64)
	var updates []abci.ValidatorUpdate
	for addr := range powers {
		updates = append(updates, abci.ValidatorUpdate{Addr: addr})
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].Addr < updates[j].Addr })
	return updates
}
