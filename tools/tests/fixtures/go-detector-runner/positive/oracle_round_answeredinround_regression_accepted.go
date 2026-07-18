package oraclefixture

type Aggregator interface {
	LatestRoundData() (uint64, int64, uint64, uint64, uint64, error)
}

type RiskEngine struct {
	oracle Aggregator
}

// BUG: critical collateral math accepts LatestRoundData output without any
// answeredInRound or round monotonicity guard.
func (r RiskEngine) ComputeCollateralValueFromRoundData(shares int64, debt int64) int64 {
	roundID, answer, startedAt, updatedAt, answeredInRound, err := r.oracle.LatestRoundData()
	if err != nil {
		return 0
	}
	_, _, _ = roundID, startedAt, answeredInRound
	if updatedAt == 0 {
		return 0
	}
	collateralValue := shares * answer / 1_000_000
	if collateralValue < debt {
		return debt - collateralValue
	}
	return collateralValue - debt
}
