package positive

import "context"

type Coins struct {
	Amount uint64
}

type BridgeMessage struct {
	Recipient      string
	ReceiverDomain uint32
	Amount         Coins
	Leaf           []byte
}

type BridgeProof struct {
	Root []byte
	Path [][]byte
}

type Verifier struct{}

func (Verifier) VerifyProof(context.Context, []byte, []byte, [][]byte) error {
	return nil
}

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(context.Context, string, string, Coins) error {
	return nil
}

type Keeper struct {
	verifier Verifier
	bank     BankKeeper
}

func (k Keeper) CompleteBridgeMessage(ctx context.Context, msg BridgeMessage, proof BridgeProof) error {
	if err := k.verifier.VerifyProof(ctx, proof.Root, msg.Leaf, proof.Path); err != nil {
		return err
	}

	recipient := msg.Recipient
	receiverDomain := msg.ReceiverDomain
	_ = receiverDomain

	return k.bank.SendCoinsFromModuleToAccount(
		ctx,
		"bridge",
		recipient,
		msg.Amount,
	)
}
