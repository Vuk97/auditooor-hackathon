package signer

// G8 fixture - go.crypto.decode_accepts_malformed_then_trusted.
// Each function models one arm of the predicate. Comments below name the
// expected detector verdict (FIRE / CLEAN) and why.

// FIRE: SigToPub decode flows to PubkeyToAddress + Check allowlist with no
// canonical guard (mirrors optimism VerifyP2PBlockSignature block_auth.go:85).
func laxRecover(a *Auth, signingHash Hash, signature []byte) error {
	pub, err := crypto.SigToPub(signingHash[:], signature[:])
	if err != nil {
		return err
	}
	addr := crypto.PubkeyToAddress(*pub)
	return a.Check(addr)
}

// CLEAN: same flow but a canonical low-S / ValidateSignatureValues guard runs
// before the decode -> canonicity enforced -> suppressed.
func guardedRecover(a *Auth, signingHash Hash, signature []byte) error {
	if err := crypto.ValidateSignatureValues(signature[64],
		r(signature[:32]), s(signature[32:64]), true); err != nil {
		return err
	}
	pub, err := crypto.SigToPub(signingHash[:], signature[:])
	if err != nil {
		return err
	}
	addr := crypto.PubkeyToAddress(*pub)
	return a.Check(addr)
}

// CLEAN: SetBytes decode into a Verify sink but a len== well-formedness guard
// gates the input -> suppressed.
func lenGuardedVerify(pk *PubKey, sig []byte, msg []byte) error {
	if len(sig) != 65 {
		return ErrBadLen
	}
	var v Big
	v.SetBytes(sig[:32])
	return pk.VerifySignature(msg, v)
}

// CLEAN: decoder present but NO trust sink (impact_contract absent) - the
// value is only logged/returned, never authorized.
func decodeThenLog(signingHash Hash, signature []byte) (string, error) {
	pub, err := crypto.SigToPub(signingHash[:], signature[:])
	if err != nil {
		return "", err
	}
	addr := crypto.PubkeyToAddress(*pub)
	return addr.Hex(), nil
}

// CLEAN: trust sink appears BEFORE the decoder - the decoded value is not the
// one being trusted (flow proxy: decoder must precede the sink).
func sinkBeforeDecode(a *Auth, who Address, signature []byte) error {
	if err := a.Check(who); err != nil {
		return err
	}
	var v Big
	v.SetBytes(signature[:32])
	return nil
}

// FIRE: asn1.Unmarshal decode of a cert then trusted via VerifyCert with no
// canonical guard.
func laxCertParse(pool *Pool, der []byte) error {
	var cert Certificate
	asn1.Unmarshal(der, &cert)
	return pool.VerifyCert(cert)
}
