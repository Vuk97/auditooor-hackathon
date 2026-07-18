// Pattern 31 — NEGATIVE fixture: every query uses the denormalized
// column predicate directly (`<Pkg>.<DenormCol>EQ(...)`) without the
// edge-join wrapper. Detector must NOT fire.
package fixture

type tokenoutputPkg struct{}
type predicateT struct{}

func (tokenoutputPkg) CreatedTransactionFinalizedHashEQ([]byte) predicateT {
	return predicateT{}
}
func (tokenoutputPkg) SpentTransactionFinalizedHashEQ([]byte) predicateT {
	return predicateT{}
}

var tokenoutput = tokenoutputPkg{}

type queryT struct{}

func (queryT) Where(...predicateT) queryT { return queryT{} }

func validateOutputsMatchSenderAndNetworkSafe(hash []byte) {
	q := queryT{}
	// SAFE (post-fix shape): denormalized predicate directly on
	// tokenoutput. No edge-join, no inner EQ wrapper.
	q.Where(tokenoutput.CreatedTransactionFinalizedHashEQ(hash))
	_ = q
}

func signTokenLoopSafe(hashes [][]byte) {
	q := queryT{}
	for _, hash := range hashes {
		// SAFE (post-fix shape): denormalized predicate.
		q.Where(tokenoutput.SpentTransactionFinalizedHashEQ(hash))
	}
	_ = q
}
