// Pattern 46 - POSITIVE fixture for
//   go.crypto.signature_replay.signer_action_missing_domain_binding
//
// The digest binds signer+action, but omits any contract/module/chain/nonce
// scope. The same signed blob can replay across sibling consumers.
package fixture

import (
	"crypto/sha256"
	"fmt"
)

type GrantBook struct {
	grants map[string]bool
}

func VerifySignature(signer string, digest [32]byte, signature []byte) bool {
	return len(signature) > 0 && signer != ""
}

func (b *GrantBook) AuthorizeModuleAction(signer string, action string, signature []byte) bool {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s|%s", signer, action)))
	if !VerifySignature(signer, digest, signature) {
		return false
	}
	b.grants[signer+"|"+action] = true
	return true
}

func (b *GrantBook) ApproveRouterCall(owner string, payloadAction string, signature []byte) bool {
	action := payloadAction
	messageHash := sha256.Sum256([]byte(owner + ":" + action))
	if !VerifySignature(owner, messageHash, signature) {
		return false
	}
	b.grants[owner+"|"+action] = true
	return true
}
