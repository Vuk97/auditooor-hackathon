// Package bank is a hermetic Go fixture for the go-dataflow backend.
//
// It models a minimal value-mover (Send) reached inter-procedurally so the SSA
// backend must cross >=2 function boundaries to connect the tainted SOURCE
// (an external `amount` parameter) to the value-moving SINK (store.Set / Transfer).
//
// Two sibling entrypoints exercise the GUARDED vs UNGUARDED def-use distinction:
//
//   UnguardedTransfer -> route -> doSend -> store.Set   (NO guard on amount)
//   GuardedTransfer   -> route -> doSend -> store.Set   (if amount<=0 { panic })
//
// The backend should mark the unguarded path unguarded=true and the guarded path
// unguarded=false (a dominating if-cond reading the sliced `amount`).
package bank

// KVStore is the value-moving / state-write sink surface (store.Set / Delete).
type KVStore struct {
	data map[string]int64
}

func NewKVStore() *KVStore { return &KVStore{data: map[string]int64{}} }

// Set is the SINK (state-write). Transfer is the SINK (value-move).
func (s *KVStore) Set(key string, val int64) { s.data[key] = val }
func (s *KVStore) Get(key string) int64      { return s.data[key] }

// Transfer is a value-move sink: it debits `from` and credits `to` by amount.
func (s *KVStore) Transfer(from, to string, amount int64) {
	s.Set(from, s.Get(from)-amount)
	s.Set(to, s.Get(to)+amount)
}

// doSend is the innermost hop: it performs the actual state-write SINK.
func doSend(store *KVStore, to string, amount int64) {
	store.Transfer("treasury", to, amount)
}

// route is an intermediate hop (boundary #1) that forwards amount unchanged.
func route(store *KVStore, to string, amount int64) {
	doSend(store, to, amount)
}

// UnguardedTransfer is the SOURCE entrypoint with NO bound on `amount`.
// def-use: param amount -> route -> doSend -> Transfer/Set  (UNGUARDED).
func UnguardedTransfer(store *KVStore, to string, amount int64) {
	route(store, to, amount)
}

// GuardedTransfer is the SOURCE entrypoint WITH a dominating guard on `amount`.
// The if-cond reads `amount` and dominates the sink-reaching call.
func GuardedTransfer(store *KVStore, to string, amount int64) {
	if amount <= 0 {
		panic("amount must be positive")
	}
	route(store, to, amount)
}
