package negative

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	store            *EventStore
	sourceChain      uint64
	destinationChain uint64
	bridgeDomain     uint32
	eventNamespace   string
}

func (d *BridgeDaemon) ForwardValue(ctx context.Context, recipient string, amount uint64) error {
	_ = ctx
	_ = recipient
	_ = amount
	return nil
}

func ValidateEventDomainBinding(event BridgeEvent, sourceChain uint64, destinationChain uint64, bridgeDomain uint32, namespace string) error {
	if event.SourceChain != sourceChain {
		return errors.New("source chain mismatch")
	}
	if event.DestinationChain != destinationChain {
		return errors.New("destination chain mismatch")
	}
	if event.BridgeDomain != bridgeDomain {
		return errors.New("bridge domain mismatch")
	}
	if event.EventNamespace != namespace {
		return errors.New("event namespace mismatch")
	}
	return nil
}

func BuildBridgeEventDomainKey(event BridgeEvent) [32]byte {
	h := sha256.New()
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], event.SourceChain)
	h.Write(scratch[:])
	binary.BigEndian.PutUint64(scratch[:], event.DestinationChain)
	h.Write(scratch[:])
	binary.BigEndian.PutUint32(scratch[:4], event.BridgeDomain)
	h.Write(scratch[:4])
	h.Write([]byte(event.EventNamespace))
	h.Write([]byte(event.EventEmitter))
	h.Write(event.TxHash[:])
	binary.BigEndian.PutUint64(scratch[:], event.LogIndex)
	h.Write(scratch[:])
	h.Write(event.EventID[:])
	return sha256.Sum256(h.Sum(nil))
}

func (d *BridgeDaemon) SettleBridgeReceipt(ctx context.Context, event BridgeEvent, receipt BridgeReceipt) error {
	if err := ValidateEventDomainBinding(
		event,
		d.sourceChain,
		d.destinationChain,
		d.bridgeDomain,
		d.eventNamespace,
	); err != nil {
		return err
	}

	key := BuildBridgeEventDomainKey(event)
	if !VerifyReceiptProof(receipt.Proof, key, receipt.Root) {
		return errors.New("invalid bridge receipt")
	}

	if d.store.Seen(key) {
		return nil
	}
	d.store.Mark(key)
	return d.ForwardValue(ctx, event.Recipient, event.Amount)
}
