// Pattern 8 — POSITIVE fixture for
//   go.cosmos.message_ordering_replay
//
// HandleMsgTransfer unmarshals a Msg-shaped payload but never references
// a sequence/nonce/Header().Height check. An attacker who replays the
// same encoded Msg in a later block would see it executed twice.
package fixture

import (
	proto "google.golang.org/protobuf/proto"
)

type MsgTransfer struct {
	From   string
	To     string
	Amount uint64
}

type Ctx struct{}

func (Ctx) Logger() interface{} { return nil }

func HandleMsgTransfer(ctx Ctx, raw []byte) error {
	var msg MsgTransfer
	if err := proto.Unmarshal(raw, &msg); err != nil {
		return err
	}
	// No sequence / nonce / Header().Height / BlockHash binding here.
	// Authorize and execute purely off message content.
	if msg.Amount == 0 {
		return nil
	}
	_ = msg.From
	_ = msg.To
	return nil
}
