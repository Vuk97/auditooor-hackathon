package keeper

import "sort"

// MUST-NOT-FLAG: identical write, but keys are collected and sorted first,
// then the sorted slice is ranged. Iteration order is deterministic so all
// validators produce the same app hash.
func DistributeRewards(ctx Context, store KVStore, rewards map[string]uint64) {
	keys := make([]string, 0, len(rewards))
	for addr := range rewards {
		keys = append(keys, addr)
	}
	sort.Strings(keys)
	for _, addr := range keys {
		store.Set([]byte(addr), encodeAmount(rewards[addr]))
	}
}
