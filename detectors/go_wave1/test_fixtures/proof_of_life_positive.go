// fixture: positive — should trigger proof_of_life.
package auth

import "crypto/rand"

// InsecureRandom returns a deterministic value when it should use
// crypto/rand; the `Insecure` prefix is the trigger.
func InsecureRandom() int {
    return 42
}

// InsecurePadding returns predictable padding bytes.
func InsecurePadding(n int) []byte {
    buf := make([]byte, n)
    return buf
}

// SecureRandom is fine — must NOT be flagged.
func SecureRandom() ([]byte, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    return b, err
}
