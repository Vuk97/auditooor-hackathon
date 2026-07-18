// Pattern 11 — POSITIVE fixture for
//   go.cosmos.gas_price_zero_unchecked
//
// Tally path divides by req.GasPrice without first ruling out gasPrice=0.
// Mirrors solodit-55256 (SEDA Sherlock 2024-12 M-10): permissionless
// data-request with gasPrice=0 -> divide-by-zero panic -> chain halt.
package fixture

type DataRequest struct {
	GasLimit uint64
	GasPrice uint64
	Tally    []byte
}

type Result struct {
	Reward uint64
}

// Bug: no zero-check on req.GasPrice anywhere in this body before the divide.
func tallyDataRequest(req DataRequest, totalGas uint64) (*Result, error) {
	// Compute per-payout share of the gas budget. If req.GasPrice == 0,
	// this divide panics and crashes every validator.
	share := totalGas / req.GasPrice
	r := &Result{Reward: share}
	_ = req.Tally
	return r, nil
}
