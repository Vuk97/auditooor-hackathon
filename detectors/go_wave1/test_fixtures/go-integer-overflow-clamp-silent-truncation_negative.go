// fixture: negative - unsafe values are rejected before accounting writes.
package keeper

import (
	"errors"
	"math"
)

const BpsDenominator uint64 = 10_000

type Pool struct {
	ProtocolFeeReserve uint64
	Reserve            uint64
}

type Market struct {
	TotalDebt uint64
}

// ApplyNarrowedProtocolFeeChecked rejects values that cannot fit the narrow type.
func ApplyNarrowedProtocolFeeChecked(pool *Pool, amountIn uint64, feeBps uint64) error {
	rawFee := amountIn * feeBps / BpsDenominator
	if rawFee > math.MaxUint32 {
		return errors.New("fee overflow")
	}
	fee32 := uint32(rawFee)
	pool.ProtocolFeeReserve += uint64(fee32)
	return nil
}

// DecayDebtRejectingUnderflow rejects excessive decay before touching debt.
func DecayDebtRejectingUnderflow(market *Market, elapsed uint64, decayRate uint64) error {
	decay := elapsed * decayRate
	if decay > market.TotalDebt {
		return errors.New("debt decay underflow")
	}
	market.TotalDebt -= decay
	return nil
}

// ApplyReserveWithdrawalChecked rejects reserve underflow before subtracting.
func ApplyReserveWithdrawalChecked(pool *Pool, sharesToAssets uint64) error {
	if sharesToAssets > pool.Reserve {
		return errors.New("reserve underflow")
	}
	pool.Reserve -= sharesToAssets
	return nil
}

// ApplyProtocolFeeWithZeroLpSpecialCase preserves full protocol fee entitlement.
func ApplyProtocolFeeWithZeroLpSpecialCase(
	pool *Pool,
	amountIn uint64,
	feeAmount uint64,
	swapFee uint64,
	protocolFee uint64,
) {
	if swapFee == protocolFee {
		pool.ProtocolFeeReserve += feeAmount
		return
	}
	protocolShare := (amountIn + feeAmount) * protocolFee / BpsDenominator
	pool.ProtocolFeeReserve += protocolShare
}
