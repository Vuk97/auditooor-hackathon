// fixture: positive - unsafe arithmetic is hidden before accounting writes.
package keeper

const BpsDenominator uint64 = 10_000

type Pool struct {
	ProtocolFeeReserve uint64
	Reserve            uint64
}

type Market struct {
	TotalDebt uint64
}

// ApplyNarrowedProtocolFee narrows the computed fee before crediting reserves.
func ApplyNarrowedProtocolFee(pool *Pool, amountIn uint64, feeBps uint64) {
	rawFee := amountIn * feeBps / BpsDenominator
	fee32 := uint32(rawFee)
	pool.ProtocolFeeReserve += uint64(fee32)
}

// DecayDebtWithSaturatingClamp hides an excessive decay amount by clamping it.
func DecayDebtWithSaturatingClamp(market *Market, elapsed uint64, decayRate uint64) {
	decay := elapsed * decayRate
	if decay > market.TotalDebt {
		decay = market.TotalDebt
	}
	market.TotalDebt -= decay
}

// ApplyUncheckedReserveWithdrawal subtracts shares from reserves without a guard.
func ApplyUncheckedReserveWithdrawal(pool *Pool, sharesToAssets uint64) {
	pool.Reserve -= sharesToAssets
}
