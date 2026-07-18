// Pattern 38 — NEGATIVE fixture: every FIPS approval call is preceded
// by an uninit-sentinel guard on the argument. Detector must NOT
// fire.
package fixture

import "fmt"

type fipsAlgorithm struct{}

func (a *fipsAlgorithm) Approved(hash int) bool { return hash != 0 }
func (a *fipsAlgorithm) Validate(hash int) bool { return hash != 0 }

type approvalPolicy struct{}

func (p *approvalPolicy) Allowed(algo int) bool { return algo != 0 }

// SAFE: explicit `hash == 0` (uninit sentinel) check before the
// approval call.
func CheckHashApprovedGuarded(hash int) (bool, error) {
	if hash == 0 {
		return false, fmt.Errorf("hash uninitialised")
	}
	algo := &fipsAlgorithm{}
	return algo.Approved(hash), nil
}

// SAFE: `IsZero(h)` helper guards before validation.
func CheckHashValidatedGuarded(h int) (bool, error) {
	if IsZero(h) {
		return false, fmt.Errorf("h uninitialised")
	}
	hashAlgo := &fipsAlgorithm{}
	return hashAlgo.Validate(h), nil
}

// SAFE: explicit `algo == 0` rejection.
func CheckAlgoAllowedGuarded(algo int) bool {
	if algo == 0 {
		return false
	}
	policy := &approvalPolicy{}
	return policy.Allowed(algo)
}

func IsZero(x int) bool { return x == 0 }
