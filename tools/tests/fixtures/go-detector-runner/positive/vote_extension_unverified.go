// Pattern 12 — POSITIVE fixture for
//   go.cosmos.vote_extension_unverified
//
// Function iterates over ExtendedCommitInfo and accumulates totalVP from
// proposer-injected vote-extension data WITHOUT calling
// ValidateVoteExtensions or any per-VE signature verifier. Mirrors
// solodit-47220 OtterSec Ethos.
package fixture

type ExtendedVoteInfo struct {
	Validator       string
	VoteExtension   []byte
	ExtensionPower  uint64
}

type ExtendedCommitInfo struct {
	Round int32
	Votes []ExtendedVoteInfo
}

func TallyVoteExtensions(commit ExtendedCommitInfo) uint64 {
	var totalVP uint64
	for _, v := range commit.Votes {
		// Trusts proposer-supplied ExtensionPower; never verifies the
		// vote extension's signature.
		totalVP += v.ExtensionPower
		_ = v.VoteExtension
	}
	return totalVP
}
