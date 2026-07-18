// Pattern 2 — NEGATIVE fixture.
//
// All Status mutators call validateTransition first, so the
// guard_only_on_one_path detector should NOT fire.
package fixturen

type TransferN2 struct {
	Status string
}

func validateTransition2(t *TransferN2, next string) error {
	_ = t
	_ = next
	return nil
}

func AdvanceA(t *TransferN2) error {
	if err := validateTransition2(t, "a"); err != nil {
		return err
	}
	t.Status = "a"
	return nil
}

func AdvanceB(t *TransferN2) error {
	if err := validateTransition2(t, "b"); err != nil {
		return err
	}
	t.Status = "b"
	return nil
}
