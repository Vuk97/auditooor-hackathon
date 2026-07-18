// Pattern 1 — POSITIVE fixture for
//   go.bitcoin.txid_equality_without_utxo_spend_check
//
// The function takes a `txid` parameter, compares it for equality
// against a persisted ID via attribute lookup, and returns true.
// It does NOT call any Validate*/Verify*/Spends*/UTXO* helper.
package fixture

type Transfer struct {
	ExpectedTxid string
}

func MatchesExpected(txid string, t *Transfer) bool {
	if txid == t.ExpectedTxid {
		return true
	}
	return false
}

// A second flavor with reversed sides — the regex must catch this.
func IsKnownTransfer(hash string, t *Transfer) bool {
	return t.ExpectedTxid == hash
}
