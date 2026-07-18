package fixtures

import (
	"crypto/sha256"
	"encoding/binary"
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

func DomainBoundEventKey(evt BridgeEvent) [32]byte {
	h := sha256.New()
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], evt.SourceChain)
	h.Write(scratch[:])
	binary.BigEndian.PutUint64(scratch[:], evt.DestinationChain)
	h.Write(scratch[:])
	h.Write([]byte(evt.EventEmitter))
	h.Write(evt.TxHash[:])
	binary.BigEndian.PutUint64(scratch[:], evt.LogIndex)
	h.Write(scratch[:])
	h.Write([]byte(evt.Recipient))
	h.Write(evt.MessageHash[:])
	return sha256.Sum256(h.Sum(nil))
}

func (d *BridgeDaemon) ConsumeBridgeEvent(evt BridgeEvent, proof []byte) error {
	key := DomainBoundEventKey(evt)
	if !VerifyBridgeProof(proof, key) {
		return errors.New("invalid proof")
	}
	if d.store.Seen(key) {
		return nil
	}
	d.store.Mark(key)
	return d.ReleaseTo(evt.Recipient, evt.Amount)
}
