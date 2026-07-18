package detectorfixture

import "math/big"

type RewardMath struct{}

func (RewardMath) CalculateRewardPayout(total uint64, fee uint64) uint64 {
	totalValue := new(big.Float).SetPrec(256).SetUint64(total)
	feeValue := new(big.Float).SetPrec(256).SetUint64(fee)
	payout := new(big.Float).SetPrec(256).Quo(totalValue, feeValue)
	out, _ := payout.Uint64()
	return out
}
