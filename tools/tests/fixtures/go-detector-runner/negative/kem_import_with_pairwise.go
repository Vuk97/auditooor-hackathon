// Pattern 43 — NEGATIVE fixture: every KEM import does an
// encap-then-decap (or named pairwise helper) check before
// returning. Detector must NOT fire.
package fixture

import (
	"bytes"
	"errors"
)

type MLKEMPrivateKey struct {
	raw []byte
	pub []byte
}

type KyberPrivateKey struct {
	raw []byte
	pub []byte
}

func (k *MLKEMPrivateKey) Encapsulate() ([]byte, []byte, error) {
	return []byte("ct"), []byte("ss"), nil
}

func (k *MLKEMPrivateKey) Decapsulate(ct []byte) ([]byte, error) {
	return []byte("ss"), nil
}

// SAFE: explicit Encapsulate / Decapsulate pairwise check.
func ImportPrivateKey(raw []byte) (*MLKEMPrivateKey, error) {
	if len(raw) < 32 {
		return nil, errors.New("too short")
	}
	k := &MLKEMPrivateKey{raw: raw}
	ct, ssEnc, err := k.Encapsulate()
	if err != nil {
		return nil, err
	}
	ssDec, err := k.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ssEnc, ssDec) {
		return nil, errors.New("pairwise mismatch")
	}
	return k, nil
}

// SAFE: named pairwise helper.
func ParseKyberPrivateKey(raw []byte) (*KyberPrivateKey, error) {
	k := &KyberPrivateKey{raw: raw}
	if err := pairwiseSelfTest(k); err != nil {
		return nil, err
	}
	return k, nil
}

func pairwiseSelfTest(k *KyberPrivateKey) error {
	return nil
}
