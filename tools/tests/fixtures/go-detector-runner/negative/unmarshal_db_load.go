// Pattern 28 — NEGATIVE fixture (Refinement 1): proto.Unmarshal of
// DB-loaded bytes that the same package marshalled at write time.
// This is canonical-only round-trip = defensive design. byte_source
// resolves to ``db_load`` and the detector must NOT fire.
package fixture

import (
	"context"

	"google.golang.org/protobuf/proto"
)

type LeafEnt struct {
	KeyTweak []byte
}

type KeyTweakProto struct{}

func (m *KeyTweakProto) Reset()         {}
func (m *KeyTweakProto) String() string { return "" }
func (m *KeyTweakProto) ProtoMessage()  {}

// SAFE under L21 ABA refinement 1 (byte_source=db_load): bytes
// originate from an ent column populated by a same-package
// proto.Marshal at write time. No re-encoding mismatch surface.
func validateLeafKeyTweak(ctx context.Context, leaf *LeafEnt) error {
	keyTweakProto := &KeyTweakProto{}
	err := proto.Unmarshal(leaf.KeyTweak, keyTweakProto)
	if err != nil {
		return err
	}
	return nil
}

// Local marshal producer at write time — confirms the DB column is
// canonical-only.
func writeLeaf(ctx context.Context, leaf *LeafEnt, kt *KeyTweakProto) error {
	bin, err := proto.Marshal(kt)
	if err != nil {
		return err
	}
	leaf.KeyTweak = bin
	return nil
}
