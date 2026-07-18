// fixture: negative - gasPrice is rejected before the division.
package fixture

import "errors"

type SafeDataRequest struct {
	GasLimit uint64
	GasPrice uint64
}

type SafeResult struct {
	Reward uint64
}

func tallyDataRequestSafe(req SafeDataRequest, totalGas uint64) (*SafeResult, error) {
	if req.GasPrice == 0 {
		return nil, errors.New("invalid gas price: zero")
	}
	share := totalGas / req.GasPrice
	return &SafeResult{Reward: share}, nil
}
