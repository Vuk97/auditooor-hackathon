// Pattern 12 — NEGATIVE fixture.
//
// Same shape as the positive fixture (iterates ExtendedCommitInfo, sums
// totalVP) but the body calls ValidateVoteExtensions on the commit info
// before trusting the per-VE power values.
package fixturen

import "errors"

type ExtendedVoteInfoN struct {
	Validator      string
	VoteExtension  []byte
	ExtensionPower uint64
}

type ExtendedCommitInfoN struct {
	Round int32
	Votes []ExtendedVoteInfoN
}

func ValidateVoteExtensions(commit ExtendedCommitInfoN, expectedHeight int64) error {
	if expectedHeight < 0 {
		return errors.New("bad height")
	}
	return nil
}

func TallyVoteExtensionsSafe(commit ExtendedCommitInfoN, h int64) (uint64, error) {
	if err := ValidateVoteExtensions(commit, h); err != nil {
		return 0, err
	}
	var totalVP uint64
	for _, v := range commit.Votes {
		totalVP += v.ExtensionPower
	}
	return totalVP, nil
}
