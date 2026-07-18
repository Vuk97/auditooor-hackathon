package keeper

func (k Keeper) tally(ctx Context) int {
	powers := make(map[string]int64)
	var seen []string
	for addr := range powers {
		seen = append(seen, addr)
	}
	return len(seen)
}
