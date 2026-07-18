package bridge

type Context struct{}
type Address string
type Coins int64

type BankKeeper struct{}

func (BankKeeper) SendCoinsFromModuleToAccount(ctx Context, module string, recipient Address, amount Coins) error {
	return nil
}

type Keeper struct {
	processedTransfers map[string]bool
	bankKeeper         BankKeeper
}

func VerifyMerkleProof(root []byte, proof []byte, transferId string, recipient Address, amount Coins) bool {
	return len(root) > 0 && len(proof) > 0 && transferId != ""
}

func (k Keeper) CompleteBridgeTransfer(
	ctx Context,
	recipient Address,
	amount Coins,
	transferId string,
	proof []byte,
	root []byte,
) error {
	if k.processedTransfers[transferId] {
		return nil
	}
	if !VerifyMerkleProof(root, proof, transferId, recipient, amount) {
		return nil
	}

	k.processedTransfers[transferId] = true
	return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "bridge", recipient, amount)
}
