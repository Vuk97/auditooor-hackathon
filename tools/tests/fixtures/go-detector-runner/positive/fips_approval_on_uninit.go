// Pattern 38 — POSITIVE fixture for
//   go.crypto.fips.approval_on_uninit
//
// Mirrors Swival #075 — Go stdlib FIPS approval gate accepted an
// uninitialised hash and reported it approved, letting non-FIPS
// code paths assert FIPS conformance.
package fixture

// Stub FIPS approval helper. Production code lives in
// `crypto/internal/fips140`. We model the call shape here.
type fipsAlgorithm struct{}

func (a *fipsAlgorithm) Approved(hash int) bool   { return hash != 0 }
func (a *fipsAlgorithm) Validate(hash int) bool   { return hash != 0 }
func (a *fipsAlgorithm) IsApproved(h int) bool    { return h != 0 }

type approvalPolicy struct{}

func (p *approvalPolicy) Allowed(algo int) bool { return algo != 0 }

// BUG: hash argument is passed to `algo.Approved(hash)` without
// first checking `hash == crypto.Hash(0)` sentinel. An uninitialised
// hash is reported as approved when the implementation only checks
// the algorithm code, not the zero-value sentinel.
func CheckHashApproved(hash int) bool {
	algo := &fipsAlgorithm{}
	return algo.Approved(hash)
}

// BUG: same shape — `hashAlgo.Validate(h)` called without a zero
// sentinel guard.
func CheckHashValidated(h int) bool {
	hashAlgo := &fipsAlgorithm{}
	return hashAlgo.Validate(h)
}

// BUG: policy.Allowed(algo) called without an uninit guard on the
// algorithm identifier.
func CheckAlgoAllowed(algo int) bool {
	policy := &approvalPolicy{}
	return policy.Allowed(algo)
}
