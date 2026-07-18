package fixtures

import (
	"crypto/sha256"
	"encoding/binary"
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

func ValidateBridgeMessageBinding(message BridgeMessage, route BridgeRoute) error {
	if message.Recipient != route.Recipient {
		return errors.New("recipient mismatch")
	}
	if message.SourceChain != route.SourceChain {
		return errors.New("source chain mismatch")
	}
	if message.DestinationChain != route.DestinationChain {
		return errors.New("destination chain mismatch")
	}
	return nil
}

func BuildBridgeMessageDomainKey(message BridgeMessage, route BridgeRoute) [32]byte {
	h := sha256.New()
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], route.SourceChain)
	h.Write(scratch[:])
	binary.BigEndian.PutUint64(scratch[:], route.DestinationChain)
	h.Write(scratch[:])
	h.Write([]byte(route.Recipient))
	h.Write(message.MessageHash[:])
	return sha256.Sum256(h.Sum(nil))
}

func (s *SubTaskRunnerImpl) RunBridgeDaemonTaskLoop(ctx Context, route BridgeRoute, message BridgeMessage, proof []byte) error {
	if err := ValidateBridgeMessageBinding(message, route); err != nil {
		return err
	}
	proofLeaf := BuildBridgeMessageDomainKey(message, route)
	if !s.proofVerifier.VerifyBridgeProof(proof, proofLeaf) {
		return errors.New("invalid bridge proof")
	}
	if s.processed.HasProcessed(proofLeaf) {
		return nil
	}
	s.processed.MarkProcessed(proofLeaf)
	return s.serviceClient.Credit(ctx, message.Recipient, message.Amount)
}
