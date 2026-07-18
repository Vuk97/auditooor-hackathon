// Pattern 1 — NEGATIVE fixture.
//
// Same shape as the positive case but explicitly calls VerifySpend, which
// the detector treats as the missing safety check.
package fixturen

type TransferN struct {
	ExpectedTxid string
}

func VerifySpend(txid string) bool {
	_ = txid
	return true
}

func MatchesExpectedSafe(txid string, t *TransferN) bool {
	if !VerifySpend(txid) {
		return false
	}
	if txid == t.ExpectedTxid {
		return true
	}
	return false
}
