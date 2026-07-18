// Pattern 46 - CLEAN control fixture.
//
// The digest binds signer+action and also binds contract/module/chain/nonce
// scope, so replay across sibling consumers is suppressed.
package fixturen

import (
	"crypto/sha256"
	"fmt"
)

type GrantBookN struct {
	grants map[string]bool
}

func VerifySignature(signer string, digest [32]byte, signature []byte) bool {
	return len(signature) > 0 && signer != ""
}

func (b *GrantBookN) AuthorizeModuleActionBound(
	signer string,
	action string,
	module string,
	contractID string,
	chainID uint64,
	nonce uint64,
	signature []byte,
) bool {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%d|%d", signer, action, module, contractID, chainID, nonce)))
	if !VerifySignature(signer, digest, signature) {
		return false
	}
	b.grants[signer+"|"+action] = true
	return true
}

func (b *GrantBookN) ApproveRouterCallBound(
	owner string,
	payloadAction string,
	module string,
	contractID string,
	chainID uint64,
	nonce uint64,
	signature []byte,
) bool {
	messageHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%d|%d", owner, payloadAction, module, contractID, chainID, nonce)))
	if !VerifySignature(owner, messageHash, signature) {
		return false
	}
	b.grants[owner+"|"+payloadAction] = true
	return true
}
