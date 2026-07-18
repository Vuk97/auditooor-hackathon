// Pattern go.bitcoin.txid_without_vout_outpoint_binding - POSITIVE fixture.
//
// Chain-watcher / exit-validation shape (Spark LEAD 1 txid-vs-UTXO class):
// the function accepts a txid parameter and compares / looks it up against a
// persisted record, but never constrains the output index (vout). An attacker
// can satisfy this check with any unrelated transaction that shares only the
// txid while targeting a different output (UTXO).
//
// The detector MUST fire because:
//   - param "txid" matches PARAM_TXID_RE
//   - body contains a txid equality check (txid == record.ExitTxid)
//   - body does NOT reference vout / outputIndex / Outpoint / UTXO index
package fixture_txid_vout_pos

// ExitRecord holds only the txid of the expected cooperative-exit tx.
// No output index is stored, so any tx with the matching txid passes.
type ExitRecord struct {
	ExitTxid string
}

// ConfirmExitByTxidOnly is the vulnerable shape: the function validates the
// cooperative-exit by txid equality alone, without checking which output of
// that transaction was actually spent. An attacker can broadcast an unrelated
// transaction with the same txid (in a fee-bumping or RBF scenario, or via
// txid malleability) targeting a different output index and still pass this
// check.
func ConfirmExitByTxidOnly(txid string, record *ExitRecord) bool {
	if txid == record.ExitTxid {
		return true
	}
	return false
}

// WatchChainExitMatch is a second flavour with reversed equality sides.
// Both flavours must be detected (reversed match via _TXID_EQ_REV).
func WatchChainExitMatch(record *ExitRecord, txid string) bool {
	return record.ExitTxid == txid
}
