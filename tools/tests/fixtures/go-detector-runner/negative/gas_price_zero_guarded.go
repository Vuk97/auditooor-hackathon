// Pattern 11 — NEGATIVE fixture.
//
// Same divide-by-gasPrice shape as the positive fixture, but the body
// explicitly rules out gasPrice == 0 before performing the division.
package fixturen

import "errors"

type DataRequestN struct {
	GasLimit uint64
	GasPrice uint64
}

type ResultN struct {
	Reward uint64
}

// Safe: the body rejects gasPrice == 0 before dividing.
func tallyDataRequestSafe(req DataRequestN, totalGas uint64) (*ResultN, error) {
	if req.GasPrice == 0 {
		return nil, errors.New("invalid gas price: zero")
	}
	share := totalGas / req.GasPrice
	return &ResultN{Reward: share}, nil
}
