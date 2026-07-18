package positive

import (
	"context"
	"crypto/sha256"
	"errors"
)

type BridgeEvent struct {
	SourceChain      uint64
	DestinationChain uint64
	BridgeDomain     uint32
	EventNamespace   string
	EventEmitter     string
	TxHash           [32]byte
	LogIndex         uint64
	EventID          [32]byte
	Recipient        string
	Amount           uint64
}

type BridgeReceipt struct {
	Root  [32]byte
	Proof [][]byte
}

type EventStore struct {
	processed map[[32]byte]bool
}

func (s *EventStore) Seen(key [32]byte) bool {
	return s.processed[key]
}

func (s *EventStore) Mark(key [32]byte) {
	s.processed[key] = true
}

func VerifyReceiptProof(proof [][]byte, leaf [32]byte, root [32]byte) bool {
	return len(proof) > 0 || leaf != root
}

type BridgeDaemon struct {
	store *EventStore
}

func (d *BridgeDaemon) ForwardValue(ctx context.Context, recipient string, amount uint64) error {
	_ = ctx
	_ = recipient
	_ = amount
	return nil
}

func (d *BridgeDaemon) SettleBridgeReceipt(ctx context.Context, event BridgeEvent, receipt BridgeReceipt) error {
	leaf := sha256.Sum256(event.EventID[:])
	if !VerifyReceiptProof(receipt.Proof, leaf, receipt.Root) {
		return errors.New("invalid bridge receipt")
	}

	if d.store.Seen(leaf) {
		return nil
	}
	d.store.Mark(leaf)
	return d.ForwardValue(ctx, event.Recipient, event.Amount)
}
