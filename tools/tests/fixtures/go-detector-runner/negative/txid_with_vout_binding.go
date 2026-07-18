// Pattern go.bitcoin.txid_without_vout_outpoint_binding - NEGATIVE fixture.
//
// The function correctly binds to the full UTXO outpoint: it checks BOTH
// the txid AND the vout (output index). The detector MUST NOT fire because
// the code constrains the specific output, not just the parent transaction.
package fixture_txid_vout_neg

// ExitOutpoint stores the full Bitcoin outpoint: txid + output index.
type ExitOutpoint struct {
	ExitTxid string
	Vout     uint32 // output index within the transaction
}

// ConfirmExitByOutpoint is the correct shape: validates the cooperative-exit
// by matching the complete outpoint (txid + vout). This correctly identifies
// the specific UTXO, preventing an attacker from substituting an unrelated
// transaction that shares only the txid but targets a different output.
func ConfirmExitByOutpoint(txid string, vout uint32, outpoint *ExitOutpoint) bool {
	if txid == outpoint.ExitTxid && vout == outpoint.Vout {
		return true
	}
	return false
}

// WatchChainFullOutpointMatch is a second flavour where the output index
// is named outputIndex instead of vout - also a safe full-outpoint binding.
type ChainExitRecord struct {
	ExitTxid    string
	OutputIndex uint32
}

func ValidateChainExit(txid string, outputIndex uint32, record *ChainExitRecord) bool {
	return txid == record.ExitTxid && outputIndex == record.OutputIndex
}
