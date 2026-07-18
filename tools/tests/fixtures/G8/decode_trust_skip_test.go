package signer

// A *_test.go file - even a lax decode-then-trust here must be SKIPPED.
func testLaxRecover(a *Auth, signingHash Hash, signature []byte) error {
	pub, err := crypto.SigToPub(signingHash[:], signature[:])
	if err != nil {
		return err
	}
	return a.Check(crypto.PubkeyToAddress(*pub))
}
