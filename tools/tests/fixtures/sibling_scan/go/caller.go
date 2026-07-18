package banking

// ProcessDeposit is the entry-point; calls validateDeposit defined in a sibling file.
func ProcessDeposit(amount int64) (int64, error) {
	if err := validateDeposit(amount); err != nil {
		return 0, err
	}
	return amount * 2, nil
}
