package positive

// DistributeFee mirrors the dydx affiliate-blocked-addr shape:
// the happy path marks status=Success, the err path silently no-ops.
func (k *Keeper) DistributeFee(ctx Ctx, addr string) error {
	err := k.transfer(addr)
	if err != nil {
		// no status update on failure — fee is silently frozen
		return err
	} else {
		k.SetStatusSuccess(addr)
		return nil
	}
}

type Keeper struct{}

func (k *Keeper) transfer(string) error          { return nil }
func (k *Keeper) SetStatusSuccess(string)        {}

type Ctx struct{}
