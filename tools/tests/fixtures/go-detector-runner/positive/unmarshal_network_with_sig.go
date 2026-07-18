// Pattern 28 — POSITIVE fixture under L21 ABA refinements 1+3:
// proto.Unmarshal of a NETWORK-RECEIVED gRPC request bytes argument
// followed by a sha256 hash + ecdsa.Verify on the parsed value.
// byte_source=network_received, signature_boundary=true → must fire.
package fixture

import (
	"crypto/ecdsa"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
)

type pbForwardRequest struct {
	Payload []byte
	Sig     []byte
	Pub     *ecdsa.PublicKey
}

type Inner struct{}

func (m *Inner) Reset()         {}
func (m *Inner) String() string { return "" }
func (m *Inner) ProtoMessage()  {}

// BUG: parses an attacker-controlled wire-format inner blob from a
// gRPC request, then verifies a signature over the raw bytes. A
// distinct re-encoding of Inner that carries unknown extension fields
// would re-encode to a different byte string but parse to the same
// Inner — sig over the original wire form, but downstream consumer
// re-encodes for signing-payload reconstruction → replay surface.
func HandleForward(req *pbForwardRequest) error {
	inner := &Inner{}
	if err := proto.Unmarshal(req.Payload, inner); err != nil {
		return err
	}
	digest := sha256.Sum256(req.Payload)
	if !ecdsa.VerifyASN1(req.Pub, digest[:], req.Sig) {
		return nil
	}
	return nil
}
