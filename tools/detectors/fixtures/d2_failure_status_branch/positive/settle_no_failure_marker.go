package positive

func (k *Keeper) Settle(id string) error {
	res, err := k.compute(id)
	if err == nil {
		k.UpdateStatusCompleted(id, res)
		return nil
	} else {
		// missing UpdateStatusFailed call → silent partial state
		return err
	}
}

type K2 struct{}

func (k *Keeper) compute(string) (int, error)      { return 0, nil }
func (k *Keeper) UpdateStatusCompleted(string, int) {}
