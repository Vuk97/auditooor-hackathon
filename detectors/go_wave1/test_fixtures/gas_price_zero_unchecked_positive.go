// fixture: positive - gasPrice is used as a divisor without a zero guard.
package fixture

type DataRequest struct {
	GasLimit uint64
	GasPrice uint64
	Tally    []byte
}

type Result struct {
	Reward uint64
}

// Mirrors solodit-55256: a permissionless request can set GasPrice to 0.
func tallyDataRequest(req DataRequest, totalGas uint64) (*Result, error) {
	share := totalGas / req.GasPrice
	_ = req.Tally
	return &Result{Reward: share}, nil
}
