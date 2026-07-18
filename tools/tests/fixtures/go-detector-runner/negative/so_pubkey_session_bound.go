// Pattern 25 — NEGATIVE fixture.
//
// VerifyOperatorSignatureSessionBound reads the session-bound identity
// (``h.config.Identifier``) before resolving the operator. Detector must
// NOT fire.
package fixturen

import (
	"context"
)

type SignatureRequestN struct {
	Payload             []byte
	Signature           []byte
	OperatorPublicKey   []byte
	SOIdentityPublicKey []byte
}

type ResolverN struct{}

type OperatorN struct {
	Pubkey []byte
}

type HandlerConfig struct {
	Identifier []byte
}

type Handler struct {
	config HandlerConfig
}

func (r *ResolverN) ResolveOperator(ctx context.Context, pubkey []byte) (*OperatorN, error) {
	return &OperatorN{Pubkey: pubkey}, nil
}

func VerifyOperatorSignature(ctx context.Context, op *OperatorN, payload, sig []byte) error {
	return nil
}

// VerifyOperatorSignatureSessionBound — defended shape: reads
// ``h.config.Identifier`` so the session-bound identity is honored.
func (h *Handler) VerifyOperatorSignatureSessionBound(ctx context.Context, r *ResolverN, req *SignatureRequestN) error {
	pubkey := req.OperatorPublicKey
	// Session-bound identity check — must match the request claim.
	sessionIdent := h.config.Identifier
	if string(sessionIdent) != string(pubkey) {
		return nil
	}
	op, err := r.ResolveOperator(ctx, pubkey)
	if err != nil {
		return err
	}
	return VerifyOperatorSignature(ctx, op, req.Payload, req.Signature)
}

// DispatchSignedToSOSessionBound — defended sister: uses
// session.OperatorPublicKey instead of req.SOIdentityPublicKey.
type Session struct {
	OperatorPublicKey []byte
}

func (h *Handler) DispatchSignedToSOSessionBound(ctx context.Context, r *ResolverN, session *Session, req *SignatureRequestN) error {
	target := session.OperatorPublicKey
	op, err := r.ResolveOperator(ctx, target)
	if err != nil {
		return err
	}
	return VerifyOperatorSignature(ctx, op, req.Payload, req.Signature)
}
