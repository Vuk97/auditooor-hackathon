package fixture

import "fmt"

type Token interface {
	Transfer(to string, amount uint64)
}

type Vault struct {
	token      Token
	treasury   string
	accruedFee uint64
}

func (v *Vault) WithdrawProtocolFee(recipient string) error {
	if recipient != v.treasury {
		return fmt.Errorf("treasury only")
	}
	feeAmount := v.accruedFee
	if feeAmount == 0 {
		return nil
	}
	v.accruedFee = 0
	v.token.Transfer(v.treasury, feeAmount)
	return nil
}
