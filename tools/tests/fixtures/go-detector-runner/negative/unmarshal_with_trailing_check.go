// Pattern 28 — NEGATIVE fixture: Unmarshal call followed by an explicit
// trailing-byte check. Detector must NOT fire.
package fixture

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
)

type Payload struct {
	Value int `json:"value"`
}

// SAFE: explicit `len(rest) == 0` guard after asn1.Unmarshal.
type Cert struct {
	Serial int
}

func ParseCertSafe(der []byte) (Cert, error) {
	var c Cert
	rest, err := asn1.Unmarshal(der, &c)
	if err != nil {
		return Cert{}, err
	}
	if len(rest) > 0 {
		return Cert{}, errors.New("trailing bytes after ASN.1 cert")
	}
	return c, nil
}

// SAFE: json.Decoder + Token check via .Empty() — represented here via
// a len(...) == 0 invariant on a sentinel residual.
func ParsePayloadSafe(buf []byte) (Payload, error) {
	var p Payload
	if err := json.Unmarshal(buf, &p); err != nil {
		return Payload{}, err
	}
	residual := []byte{}
	if len(residual) != 0 {
		return Payload{}, errors.New("trailing bytes")
	}
	return p, nil
}
