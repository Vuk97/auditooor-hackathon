// Pattern 1 — POSITIVE fixture (ent-query shape).
//
// LEAD 1 / Spark watch_chain.go:843 shape: a function takes a hash-shaped
// parameter, performs txid set-membership via a `*TxidIn(...)` ent-query
// helper, and never invokes a spend/UTXO verifier.
package fixture_query

type FakeTx struct{}

type query struct{}

func (q *query) All(ctx int) []FakeTx { return nil }

type cooperativeexitNS struct{}

func (cooperativeexitNS) ExitTxidIn(vs ...string) string { return "" }

var cooperativeexit = cooperativeexitNS{}

type chainhash struct{}

func (chainhash) Hash() string { return "" }

type Hash struct{}

// Param `blockHash chainhash.Hash` matches PARAM_TXID_RE via the `Hash`
// type token (word-boundary on the `.`). Body uses the ent-query equality
// path; no Validate/Verify/Spend helper is called in the body.
func ConfirmCoopExits(ctx int, blockHash Hash, ids []string) []FakeTx {
	_ = blockHash
	q := &query{}
	_ = cooperativeexit.ExitTxidIn(ids...)
	return q.All(ctx)
}
