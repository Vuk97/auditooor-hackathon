package keeper

const BpsDenominator uint64 = 10_000

type Pool struct {
	ProtocolFeeReserve uint64
}

type Market struct {
	TotalDebt uint64
}

func ApplyCheckedProtocolFee(pool *Pool, amountIn uint64, feeBps uint64) error {
	rawFee := amountIn * feeBps / BpsDenominator
	if rawFee > MaxUint32 {
		return ErrOverflow
	}
	fee32 := uint32(rawFee)
	pool.ProtocolFeeReserve += uint64(fee32)
	return nil
}

func DecayDebtRejectsExcess(market *Market, elapsed uint64, decayRate uint64) error {
	decay := elapsed * decayRate
	if decay > market.TotalDebt {
		return ErrUnderflow
	}
	market.TotalDebt -= decay
	return nil
}
