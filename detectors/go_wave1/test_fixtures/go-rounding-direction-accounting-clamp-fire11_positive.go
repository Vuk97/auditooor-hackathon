package keeper

const BpsDenominator uint64 = 10_000

type Pool struct {
	ProtocolFeeReserve uint64
}

type Market struct {
	TotalDebt uint64
}

func ApplyNarrowedProtocolFee(pool *Pool, amountIn uint64, feeBps uint64) {
	rawFee := amountIn * feeBps / BpsDenominator
	fee32 := uint32(rawFee)
	pool.ProtocolFeeReserve += uint64(fee32)
}

func DecayDebtWithSaturatingClamp(market *Market, elapsed uint64, decayRate uint64) {
	decay := elapsed * decayRate
	if decay > market.TotalDebt {
		decay = market.TotalDebt
	}
	market.TotalDebt -= decay
}
