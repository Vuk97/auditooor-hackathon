// fixture: negative — must not trigger proof_of_life.
package auth

import "crypto/rand"

func SecureRandom() ([]byte, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    return b, err
}

func SafePadding(n int) []byte {
    return make([]byte, n)
}
