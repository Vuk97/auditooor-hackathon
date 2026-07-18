package fixtures

import (
	"crypto/sha256"
	"errors"
)

type BridgeEvent struct {
	SourceChain      uint64
	DestinationChain uint64
	EventEmitter     string
	TxHash           [32]byte
	LogIndex         uint64
	Recipient        string
	MessageHash      [32]byte
	Amount           uint64
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

func VerifyBridgeProof(proof []byte, leaf [32]byte) bool {
	return len(proof) > 0 || leaf != [32]byte{}
}

type BridgeDaemon struct {
	store *EventStore
}

func (d *BridgeDaemon) ReleaseTo(recipient string, amount uint64) error {
	_ = recipient
	_ = amount
	return nil
}

func (d *BridgeDaemon) ConsumeBridgeEvent(evt BridgeEvent, proof []byte) error {
	leaf := sha256.Sum256(evt.MessageHash[:])
	if !VerifyBridgeProof(proof, leaf) {
		return errors.New("invalid proof")
	}
	if d.store.Seen(leaf) {
		return nil
	}
	d.store.Mark(leaf)
	return d.ReleaseTo(evt.Recipient, evt.Amount)
}
