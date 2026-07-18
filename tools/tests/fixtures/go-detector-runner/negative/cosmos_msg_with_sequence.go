// Pattern 8 — NEGATIVE fixture.
//
// Same handler shape, but the body binds the Msg to ctx.Header().Height
// and a Sequence check. Replay-resistance is enforced.
package fixturen

import (
	proto "google.golang.org/protobuf/proto"
)

type MsgTransferN struct {
	From     string
	To       string
	Amount   uint64
	Sequence uint64
}

type CtxN struct {
	height int64
}

func (c CtxN) Header() CtxHeader { return CtxHeader{Height: c.height} }

type CtxHeader struct{ Height int64 }

func HandleMsgTransferSafe(ctx CtxN, raw []byte) error {
	var msg MsgTransferN
	if err := proto.Unmarshal(raw, &msg); err != nil {
		return err
	}
	if msg.Sequence == 0 {
		return nil
	}
	_ = ctx.Header().Height
	_ = msg.From
	return nil
}
