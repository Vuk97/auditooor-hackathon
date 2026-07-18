package fixture

type Token interface {
	Transfer(to string, amount uint64)
}

type Vault struct {
	token      Token
	accruedFee uint64
}

func (v *Vault) WithdrawProtocolFee(recipient string) error {
	feeAmount := v.accruedFee
	if feeAmount == 0 {
		return nil
	}
	v.accruedFee = 0
	v.token.Transfer(recipient, feeAmount)
	return nil
}
