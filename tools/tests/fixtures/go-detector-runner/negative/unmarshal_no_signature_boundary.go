// Pattern 28 — NEGATIVE fixture (Refinement 3): permissive parser
// (proto.Unmarshal) of unknown-source bytes with NO downstream
// signature/hash boundary in the same body. byte_source=unknown +
// signature_boundary=false → suppressed.
package fixture

import "google.golang.org/protobuf/proto"

type Cfg struct{}

func (m *Cfg) Reset()         {}
func (m *Cfg) String() string { return "" }
func (m *Cfg) ProtoMessage()  {}

// SAFE under L21 ABA refinement 3: no Verify / sha256 / bytes.Equal
// hash-shaped check in the same body, so distinct re-encodings have
// no impact channel here.
func ParseCfg(blob []byte) (*Cfg, error) {
	c := &Cfg{}
	if err := proto.Unmarshal(blob, c); err != nil {
		return nil, err
	}
	return c, nil
}
