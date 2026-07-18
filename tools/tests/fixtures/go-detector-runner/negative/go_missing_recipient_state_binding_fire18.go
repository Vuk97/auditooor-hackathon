package fixtures

type Fire18SafeContext struct{}

type Fire18SafeBridgeEvent struct {
	Recipient   string
	SourceChain string
	EventID     string
	Commitment  []byte
	Amount      int64
}

type Fire18SafeStore struct{}

func (s Fire18SafeStore) MarkClaimed(recipient string, eventID string) {}

type Fire18SafeKeeper struct {
	store    Fire18SafeStore
	credits  map[string]int64
	forwards []string
}

func (k *Fire18SafeKeeper) ValidateRecipientBinding(
	ctx Fire18SafeContext,
	sourceChain string,
	eventID string,
	recipient string,
	commitment []byte,
) error {
	return nil
}

func (k *Fire18SafeKeeper) ForwardWithdrawal(ctx Fire18SafeContext, recipient string, amount int64) error {
	k.forwards = append(k.forwards, recipient)
	return nil
}

func (k *Fire18SafeKeeper) FinalizeBridgeCredit(ctx Fire18SafeContext, event Fire18SafeBridgeEvent) error {
	recipient := event.Recipient
	if err := k.ValidateRecipientBinding(
		ctx,
		event.SourceChain,
		event.EventID,
		recipient,
		event.Commitment,
	); err != nil {
		return err
	}
	k.credits[recipient] += event.Amount
	k.store.MarkClaimed(recipient, event.EventID)
	return k.ForwardWithdrawal(ctx, recipient, event.Amount)
}
