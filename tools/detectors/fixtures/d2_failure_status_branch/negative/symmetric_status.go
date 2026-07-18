package negative

// Settle marks success on the happy path AND failure on the error path —
// symmetric, should NOT fire the asymmetry detector.
func (k *Keeper) Settle(id string) error {
	res, err := k.compute(id)
	if err != nil {
		k.SetStatusFailed(id)
		return err
	} else {
		k.SetStatusSuccess(id, res)
		return nil
	}
}

type Keeper struct{}

func (k *Keeper) compute(string) (int, error) { return 0, nil }
func (k *Keeper) SetStatusFailed(string)      {}
func (k *Keeper) SetStatusSuccess(string, int){}
