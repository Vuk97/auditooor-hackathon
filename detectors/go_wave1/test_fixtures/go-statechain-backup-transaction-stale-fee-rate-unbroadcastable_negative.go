package statechain

type BackupTx struct {
	Bytes []byte
}

type Wallet struct {
	BackupTx BackupTx
}

func BuildBackupTransaction(w Wallet, currentFeeRate int64) []byte {
	if currentFeeRate > 0 {
		UpdateBackupTxFeeRate(&w, currentFeeRate)
		WarnBeforeCSVExpiry(w.BackupTx)
	}
	return SerializeBackupTx(w.BackupTx, currentFeeRate)
}

func UpdateBackupTxFeeRate(w *Wallet, currentFeeRate int64) {
	_ = currentFeeRate
	_ = w
}

func WarnBeforeCSVExpiry(tx BackupTx) {
	_ = tx
}

func SerializeBackupTx(tx BackupTx, feeRate int64) []byte {
	_ = feeRate
	return tx.Bytes
}
