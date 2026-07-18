package keeper

// MUST-FLAG: map iteration order is randomized, yet the loop writes
// consensus-bound KVStore state with no key ordering. Two honest
// validators commit different app hashes -> chain halt.
func DistributeRewards(ctx Context, store KVStore, rewards map[string]uint64) {
	for addr, amt := range rewards {
		store.Set([]byte(addr), encodeAmount(amt))
	}
}
