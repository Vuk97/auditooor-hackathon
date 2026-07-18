package oraclefixture

import "fmt"

type Aggregator interface {
	LatestRoundData() (uint64, int64, uint64, uint64, uint64, error)
}

type RiskEngine struct {
	oracle    Aggregator
	lastRound uint64
}

func (r RiskEngine) ComputeCollateralValueFromGuardedRoundData(shares int64, debt int64) (int64, error) {
	roundID, answer, startedAt, updatedAt, answeredInRound, err := r.oracle.LatestRoundData()
	if err != nil {
		return 0, err
	}
	if answeredInRound < roundID {
		return 0, fmt.Errorf("stale oracle round")
	}
	if answeredInRound <= r.lastRound {
		return 0, fmt.Errorf("non-monotonic oracle round")
	}
	_, _ = startedAt, updatedAt
	collateralValue := shares * answer / 1_000_000
	if collateralValue < debt {
		return debt - collateralValue, nil
	}
	return collateralValue - debt, nil
}
