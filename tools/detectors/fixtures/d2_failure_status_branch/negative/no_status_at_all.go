package negative

// A pure compute helper with no status writes on either branch — not the
// asymmetry shape, should not fire.
func Compute(x int) (int, error) {
	if x < 0 {
		return 0, ErrNeg
	} else {
		return x * 2, nil
	}
}

type errNeg struct{}

func (errNeg) Error() string { return "neg" }

var ErrNeg = errNeg{}
