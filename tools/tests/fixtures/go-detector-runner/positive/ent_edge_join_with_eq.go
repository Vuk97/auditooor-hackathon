// Pattern 31 — POSITIVE fixture for
//   go.spark.ent.edge_join_with_eq_when_denormalized_column_exists
//
// Mirrors Spark commit e330cd3458 (PR #6416) — replaces an ent
// edge-join `Has<Edge>With(<Pkg>.<Col>EQ(...))` with a denormalized
// predicate `<Pkg>.<DenormCol>EQ(...)`. The pattern fires on the
// pre-fix shape; downstream triage (manual or follow-up loop) must
// confirm whether the inner column has a denormalized mirror.
package fixture

// Stub package types so the file compiles.
type tokenoutputPkg struct{}
type tokentransactionPkg struct{}
type predicateT struct{}

func (tokenoutputPkg) HasOutputCreatedTokenTransactionWith(...predicateT) predicateT {
	return predicateT{}
}
func (tokenoutputPkg) HasOutputSpentTokenTransactionWith(...predicateT) predicateT {
	return predicateT{}
}
func (tokentransactionPkg) FinalizedTokenTransactionHashEQ([]byte) predicateT {
	return predicateT{}
}

var tokenoutput = tokenoutputPkg{}
var tokentransaction = tokentransactionPkg{}

type queryT struct{}

func (queryT) Where(...predicateT) queryT { return queryT{} }

func validateOutputsMatchSenderAndNetwork(hash []byte) {
	q := queryT{}
	// BUG (pre-fix shape): edge-join when a denormalized column exists.
	q.Where(
		tokenoutput.HasOutputCreatedTokenTransactionWith(
			tokentransaction.FinalizedTokenTransactionHashEQ(hash),
		),
	)
	_ = q
}

func signTokenLoop(hashes [][]byte) {
	q := queryT{}
	for _, hash := range hashes {
		// BUG (adjacent unfixed site at internal_sign_token_handler.go:428):
		// edge-join + EQ on the same join column.
		q.Where(tokenoutput.HasOutputSpentTokenTransactionWith(tokentransaction.FinalizedTokenTransactionHashEQ(hash)))
	}
	_ = q
}
