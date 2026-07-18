// Pattern 28 — POSITIVE fixture for
//   go.crypto.unmarshal.trailing_bytes_accepted
//
// Function calls Unmarshal-family API and does NOT subsequently check
// that the input was fully consumed. Mirrors Swival #011/#039/#056.
//
// L21 ABA refinement: pattern now requires (a) PERMISSIVE parser
// (proto/asn1/cbor; NOT json — stdlib rejects trailing), (b)
// byte_source != db_load, (c) NOT (unknown source AND no signature
// boundary). Both functions below satisfy these.
package fixture

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"

	"google.golang.org/protobuf/proto"
)

type Cert struct {
	Serial int
}

type Msg struct{}

func (m *Msg) Reset()         {}
func (m *Msg) String() string { return "" }
func (m *Msg) ProtoMessage()  {}

// BUG #1: asn1.Unmarshal returns the trailing rest, but the caller
// throws it away. byte_source=unknown, signature_boundary=true (the
// parsed cert.Serial feeds an ecdsa.Verify).
func ParseCert(der []byte, sig []byte, pub *ecdsa.PublicKey) (Cert, error) {
	var c Cert
	_, err := asn1.Unmarshal(der, &c)
	if err != nil {
		return Cert{}, err
	}
	digest := sha256.Sum256(der)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return Cert{}, asn1.StructuralError{Msg: "bad sig"}
	}
	return c, nil
}

// BUG #2: proto.Unmarshal of decrypted plaintext (attacker-chosen),
// then a downstream sha256 hash on the decoded form (signature
// boundary). byte_source=decrypted_plaintext.
func DecryptAndParseShare(ciphertext []byte) (*Msg, error) {
	plaintext, err := eciesgo.Decrypt(nil, ciphertext)
	if err != nil {
		return nil, err
	}
	m := &Msg{}
	if err := proto.Unmarshal(plaintext, m); err != nil {
		return nil, err
	}
	_ = sha256.Sum256(plaintext)
	return m, nil
}

// Stub package alias to make the marker import explicit (fixture is
// not compiled — only text-scanned).
var eciesgo = struct {
	Decrypt func(any, []byte) ([]byte, error)
}{
	Decrypt: func(_ any, ct []byte) ([]byte, error) { return ct, nil },
}
