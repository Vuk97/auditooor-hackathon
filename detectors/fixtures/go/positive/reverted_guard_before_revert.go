// Fixture: state BEFORE the revert commit (the guard fn exists here).
// validate_transfer_leaves_status is present — this is the guard that
// was later reverted.

package transfer

import "errors"

// Vault holds a simple balance.
type Vault struct {
	Balance uint64
}

// validateTransferLeavesStatus guards against transfers on exited leaves.
func validateTransferLeavesStatus(leafStatus string) error {
	if leafStatus == "exited" {
		return errors.New("leaf already exited to L1; transfer rejected")
	}
	return nil
}

// Transfer executes a transfer after validating leaf status.
func (v *Vault) Transfer(amount uint64, leafStatus string) error {
	if err := validateTransferLeavesStatus(leafStatus); err != nil {
		return err
	}
	v.Balance += amount
	return nil
}
