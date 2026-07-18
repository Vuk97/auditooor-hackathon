package banking

import "errors"

// validateDeposit checks that the amount is positive and within limits.
func validateDeposit(amount int64) error {
	if amount <= 0 {
		return errors.New("amount must be positive")
	}
	if amount > 1_000_000 {
		return errors.New("amount exceeds limit")
	}
	return nil
}
