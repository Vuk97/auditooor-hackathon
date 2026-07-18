package d8_keeper_helper

// Keeper helper that writes state without an authority check.
// The receiver type ends in "Keeper" (matches MSGSERVER_TYPE_RE's Keeper
// branch in default mode). In production Cosmos code these are internal
// state-writing helpers - authorization is enforced at the registered
// MsgServer handler one layer above (e.g. x/insurance/keeper/msg_server.go
// calls CreateInsuranceFund after checking k.authority).
//
// Expected behavior:
//   - default mode (--entrypoints-only=False): Pattern A FIRES
//     (MSGSERVER_TYPE_RE matches the "Keeper" suffix)
//   - --entrypoints-only mode: Pattern A does NOT fire
//     (ENTRYPOINT_RECEIVER_RE requires msgServer/Msg_Server only)

type InsuranceFundKeeper struct {
	store KVStore
}

type KVStore interface {
	Set(key, val []byte)
	Delete(key []byte)
}

type KeeperCtx struct {
	dummy int
}

func (k *InsuranceFundKeeper) CreateInsuranceFund(ctx KeeperCtx, marketID string, deposit int) {
	// Internal helper - the MsgServer above already checked k.authority before
	// delegating here. No authority check in this helper body.
	store.Set([]byte(marketID), []byte{byte(deposit)})
}

func (k *InsuranceFundKeeper) DeactivateContract(ctx KeeperCtx, addr string) {
	// Another internal helper - guarded at the Msg dispatch layer, not here.
	store.Delete([]byte(addr))
}
