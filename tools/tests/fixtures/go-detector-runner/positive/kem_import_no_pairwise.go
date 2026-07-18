// Pattern 43 — POSITIVE fixture for
//   go.crypto.kem.imported_key_skips_pairwise_consistency_test
//
// Mirrors Swival #026 — KEM key import without an encap-then-decap
// pairwise consistency self-test. NIST SP 800-56C / FIPS 203 require
// the self-test before treating an imported KEM keypair as healthy.
package fixture

import "errors"

type MLKEMPrivateKey struct {
	raw []byte
}

type KyberPrivateKey struct {
	raw []byte
}

type HPKEPrivateKey struct {
	raw []byte
}

// BUG: ImportPrivateKey returns the parsed private key without an
// encap-then-decap pairwise consistency test.
func ImportPrivateKey(raw []byte) (*MLKEMPrivateKey, error) {
	if len(raw) < 32 {
		return nil, errors.New("too short")
	}
	return &MLKEMPrivateKey{raw: raw}, nil
}

// BUG: ParseKyberPrivateKey skips the pairwise self-test.
func ParseKyberPrivateKey(raw []byte) (*KyberPrivateKey, error) {
	if len(raw) < 32 {
		return nil, errors.New("too short")
	}
	return &KyberPrivateKey{raw: raw}, nil
}

// BUG: LoadHPKEPrivateKey returns without pairwise check.
func LoadHPKEPrivateKey(raw []byte) (*HPKEPrivateKey, error) {
	return &HPKEPrivateKey{raw: raw}, nil
}
