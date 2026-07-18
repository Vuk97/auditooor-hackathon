// fixture: positive - truncation residuals are assigned to attacker-favorable sinks.
package keeper

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

type Keeper struct {
	FeeCredits  map[string]uint64
	AccountDust map[string]uint64
	ModuleDust  uint64
	Rewards     map[string]uint64
}

// DistributeFeeRemainderToFirstParticipant gives modulo dust to participant zero.
func (k Keeper) DistributeFeeRemainderToFirstParticipant(participants []string, totalFee uint64) error {
	feeShare := totalFee / uint64(len(participants))
	remainder := totalFee % uint64(len(participants))
	for _, participant := range participants {
		k.FeeCredits[participant] += feeShare
	}
	k.FeeCredits[participants[0]] += remainder
	return nil
}

// CreditSdkIntResidualToAttacker gives sdk.Int-style residual value to attacker.
func (k Keeper) CreditSdkIntResidualToAttacker(attacker string, accounts []string, totalFee Int) error {
	share := totalFee.QuoRaw(int64(len(accounts)))
	residual := totalFee.Sub(share.MulRaw(int64(len(accounts))))
	k.AccountDust[attacker] += residual.Amount
	return nil
}

// SendLegacyDecimalDustToModule truncates legacy decimal dust into module state.
func (k Keeper) SendLegacyDecimalDustToModule(module string, feeDec LegacyDec) error {
	whole := feeDec.TruncateInt()
	dust := feeDec.Sub(NewLegacyDecFromInt(whole)).TruncateInt()
	k.ModuleDust += dust.Amount
	return nil
}

// AssignRewardLeftoverToFirstReceiver gives split leftovers to receiver zero.
func (k Keeper) AssignRewardLeftoverToFirstReceiver(receivers []string, totalRewards uint64) error {
	rewardShare := totalRewards / uint64(len(receivers))
	leftover := totalRewards - rewardShare*uint64(len(receivers))
	for _, receiver := range receivers {
		k.Rewards[receiver] += rewardShare
	}
	k.Rewards[receivers[0]] += leftover
	return nil
}
