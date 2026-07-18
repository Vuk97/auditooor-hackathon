package positive

import "context"

type IncomingMessage struct {
	Amount uint64
}

type StableManagement struct{}

func (StableManagement) Cap(context.Context) uint64 {
	return 0
}

func (StableManagement) SetNewCap(context.Context, uint64) error {
	return nil
}

type USC struct{}

func (USC) TotalSupply(context.Context) uint64 {
	return 0
}

type Keeper struct {
	stable StableManagement
	usc    USC
}

func (k Keeper) ApplyIncomingMessage(ctx context.Context, msg IncomingMessage) error {
	currentCap := k.stable.Cap(ctx)
	totalSupply := k.usc.TotalSupply(ctx)
	top := currentCap
	if totalSupply > top {
		top = totalSupply
	}

	return k.stable.SetNewCap(ctx, top+msg.Amount)
}
