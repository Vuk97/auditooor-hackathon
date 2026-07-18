package fixtures

import (
	"crypto/sha256"
	"errors"
)

type Context struct{}
type AccAddress string
type Coins uint64

type BridgeRoute struct {
	SourceChain      uint64
	DestinationChain uint64
	Recipient        AccAddress
}

type BridgeMessage struct {
	SourceChain      uint64
	DestinationChain uint64
	Recipient        AccAddress
	MessageHash      [32]byte
	Amount           Coins
}

type ProofVerifier struct{}

func (ProofVerifier) VerifyBridgeProof(proof []byte, leaf [32]byte) bool {
	return len(proof) > 0 || leaf != [32]byte{}
}

type ProcessedStore struct {
	seen map[[32]byte]bool
}

func (s ProcessedStore) HasProcessed(key [32]byte) bool {
	return s.seen[key]
}

func (s ProcessedStore) MarkProcessed(key [32]byte) {
	s.seen[key] = true
}

type BridgeServiceClient struct{}

func (BridgeServiceClient) Credit(ctx Context, recipient AccAddress, amount Coins) error {
	_ = ctx
	_ = recipient
	_ = amount
	return nil
}

type SubTaskRunnerImpl struct {
	proofVerifier ProofVerifier
	processed     ProcessedStore
	serviceClient BridgeServiceClient
}

func (s *SubTaskRunnerImpl) RunBridgeDaemonTaskLoop(ctx Context, route BridgeRoute, message BridgeMessage, proof []byte) error {
	expectedRecipient := route.Recipient
	_ = expectedRecipient
	expectedDestinationChain := route.DestinationChain
	_ = expectedDestinationChain

	proofLeaf := sha256.Sum256(message.MessageHash[:])
	if !s.proofVerifier.VerifyBridgeProof(proof, proofLeaf) {
		return errors.New("invalid bridge proof")
	}
	if s.processed.HasProcessed(proofLeaf) {
		return nil
	}
	s.processed.MarkProcessed(proofLeaf)
	return s.serviceClient.Credit(ctx, message.Recipient, message.Amount)
}
