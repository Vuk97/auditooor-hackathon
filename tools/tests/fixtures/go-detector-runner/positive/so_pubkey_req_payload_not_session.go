// Pattern 25 — POSITIVE fixture for
//   go.spark.so_pubkey.req_payload_not_session
//
// VerifyOperatorSignatureFromReq lifts the SO public key from the
// request payload (``req.OperatorPublicKey``) and feeds it into a
// downstream signature verifier WITHOUT first reading the
// session-bound identity. A malicious caller can pin any pubkey here
// and the verifier accepts.
//
// Two sister functions in the same file ensure the detector flags both.
package fixture

import (
	"context"
)

type SignatureRequest struct {
	Payload             []byte
	Signature           []byte
	OperatorPublicKey   []byte
	SOIdentityPublicKey []byte
}

type Resolver struct{}

type Operator struct {
	Pubkey []byte
}

func (r *Resolver) ResolveOperator(ctx context.Context, pubkey []byte) (*Operator, error) {
	return &Operator{Pubkey: pubkey}, nil
}

func VerifyOperatorSignature(ctx context.Context, op *Operator, payload, sig []byte) error {
	return nil
}

// VerifyOperatorSignatureFromReq — bug shape: trusts req.OperatorPublicKey.
func VerifyOperatorSignatureFromReq(ctx context.Context, r *Resolver, req *SignatureRequest) error {
	pubkey := req.OperatorPublicKey
	op, err := r.ResolveOperator(ctx, pubkey)
	if err != nil {
		return err
	}
	return VerifyOperatorSignature(ctx, op, req.Payload, req.Signature)
}

// DispatchSignedToSO — sister bug-shape: trusts req.SOIdentityPublicKey
// and dials the operator over RPC without a session-bound check.
func DispatchSignedToSO(ctx context.Context, r *Resolver, req *SignatureRequest) error {
	target := req.SOIdentityPublicKey
	op, err := r.ResolveOperator(ctx, target)
	if err != nil {
		return err
	}
	return VerifyOperatorSignature(ctx, op, req.Payload, req.Signature)
}
