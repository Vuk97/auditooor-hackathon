package fixtures

type Fire18Context struct{}

type Fire18BridgeEvent struct {
	Recipient   string
	SourceChain string
	EventID     string
	Commitment  []byte
	Amount      int64
}

type Fire18Store struct{}

func (s Fire18Store) MarkClaimed(recipient string, eventID string) {}

type Fire18Keeper struct {
	store    Fire18Store
	credits  map[string]int64
	forwards []string
}

func (k *Fire18Keeper) ForwardWithdrawal(ctx Fire18Context, recipient string, amount int64) error {
	k.forwards = append(k.forwards, recipient)
	return nil
}

func (k *Fire18Keeper) FinalizeBridgeCredit(ctx Fire18Context, event Fire18BridgeEvent) error {
	recipient := event.Recipient
	k.credits[recipient] += event.Amount
	k.store.MarkClaimed(recipient, event.EventID)
	return k.ForwardWithdrawal(ctx, recipient, event.Amount)
}
