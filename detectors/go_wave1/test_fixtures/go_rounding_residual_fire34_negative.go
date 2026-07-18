// fixture: negative - residuals are rejected, carried, bounded, or allocated to last participant.
package keeper

import "errors"

type Int struct {
	Amount uint64
}

func (i Int) QuoRaw(n int64) Int {
	return i
}

func (i Int) MulRaw(n int64) Int {
	return i
}

func (i Int) Sub(other Int) Int {
	return i
}

func (i Int) GT(other Int) bool {
	return false
}

type LegacyDec struct {
	Amount uint64
}

func (d LegacyDec) TruncateInt() Int {
	return Int{Amount: d.Amount}
}

func (d LegacyDec) Sub(other LegacyDec) LegacyDec {
	return d
}

func NewLegacyDecFromInt(i Int) LegacyDec {
	return LegacyDec{Amount: i.Amount}
}

var MaxDust = Int{Amount: 1}

type Keeper struct {
	FeeCredits     map[string]uint64
	RemainderCarry uint64
	RoundingCarry  uint64
	DebugRemainder uint64
}

// RejectFeeRemainder rejects non-exact fee splits before crediting anyone.
func (k Keeper) RejectFeeRemainder(participants []string, totalFee uint64) error {
	feeShare := totalFee / uint64(len(participants))
	remainder := totalFee % uint64(len(participants))
	if remainder != 0 {
		return errors.New("non-exact fee split")
	}
	for _, participant := range participants {
		k.FeeCredits[participant] += feeShare
	}
	return nil
}

// CarryFeeRemainder explicitly carries dust forward for later settlement.
func (k Keeper) CarryFeeRemainder(participants []string, totalFee uint64) error {
	feeShare := totalFee / uint64(len(participants))
	remainder := totalFee % uint64(len(participants))
	for _, participant := range participants {
		k.FeeCredits[participant] += feeShare
	}
	k.RemainderCarry += remainder
	return nil
}

// AssignRemainderToLastParticipant uses a documented last-participant path.
func (k Keeper) AssignRemainderToLastParticipant(participants []string, totalFee uint64) error {
	feeShare := totalFee / uint64(len(participants))
	remainder := totalFee % uint64(len(participants))
	for _, participant := range participants {
		k.FeeCredits[participant] += feeShare
	}
	k.FeeCredits[participants[len(participants)-1]] += remainder
	return nil
}

// BoundLegacyDecimalDust caps decimal conversion dust before carrying it.
func (k Keeper) BoundLegacyDecimalDust(feeDec LegacyDec) error {
	whole := feeDec.TruncateInt()
	dust := feeDec.Sub(NewLegacyDecFromInt(whole)).TruncateInt()
	if dust.GT(MaxDust) {
		return errors.New("dust too large")
	}
	k.RoundingCarry += dust.Amount
	return nil
}

// StoreRemainderMetric keeps a rounded bucket in debug state only.
func (k Keeper) StoreRemainderMetric(totalFee uint64) error {
	remainder := totalFee % 10
	k.DebugRemainder = remainder
	return nil
}
