package statechain

type BackupTx struct {
	Bytes []byte
}

type Wallet struct {
	BackupTx      BackupTx
	signedFeeRate int64
}

func BuildBackupTransaction(w Wallet, currentFeeRate int64) []byte {
	tx := w.BackupTx
	feeRate := w.signedFeeRate
	_ = currentFeeRate
	return SerializeBackupTx(tx, feeRate)
}

func SerializeBackupTx(tx BackupTx, feeRate int64) []byte {
	_ = feeRate
	return tx.Bytes
}
