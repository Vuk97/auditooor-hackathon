// Fixture: state AFTER the revert commit (the guard fn was removed).
// validateTransferLeavesStatus is gone — this is the audit-pin state for
// the Go reverted-guard synthetic test. Live code is unprotected.

package transfer

// Vault holds a simple balance.
type Vault struct {
	Balance uint64
}

// Transfer executes a transfer without validating leaf status.
// Guard was here; reverted by "Trust mitigations" commit.
func (v *Vault) Transfer(amount uint64, leafStatus string) error {
	v.Balance += amount
	return nil
}
