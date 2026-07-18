// Pattern 2 — POSITIVE fixture for
//   go.statemachine.guard_only_on_one_path
//
// One function calls validateTransition; a sibling in the same file
// mutates transfer.Status without calling any guard.
package fixture

type Node struct {
	Status string
}

type Transfer2 struct {
	Status string
}

func validateTransition(t *Transfer2, next string) error {
	_ = t
	_ = next
	return nil
}

func GuardedAdvance(t *Transfer2) error {
	if err := validateTransition(t, "advanced"); err != nil {
		return err
	}
	t.Status = "advanced"
	return nil
}

// SIBLING — mutates Status with no guard call. Detector should flag this.
func SilentlyAdvance(t *Transfer2) {
	transfer := t
	transfer.Status = "advanced"
}
