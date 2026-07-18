// Pattern 29 — NEGATIVE fixture: every fmt.Errorf returned from this
// RPC handler is wrapped via errors.InvalidArgument*(). Detector must
// NOT fire.
package fixture

import (
	"context"
	"fmt"
)

type pb struct{}
type QueryNodesRequest struct {
	OwnerIdentityPublicKey []byte
	NodeIds                []string
}
type QueryNodesResponse struct{}

type uuidPkg struct{}

func (uuidPkg) Parse(_ string) (struct{}, error) { return struct{}{}, nil }

var uuid = uuidPkg{}

type keysPkg struct{}

func (keysPkg) ParsePublicKey(_ []byte) (struct{}, error) { return struct{}{}, nil }

var keys = keysPkg{}

type errorsPkg struct{}

func (errorsPkg) InvalidArgumentMalformedField(_ error) error    { return nil }
func (errorsPkg) InvalidArgumentMalformedKey(_ error) error      { return nil }

var errs = errorsPkg{}

// SAFE: every parse failure routes through an errors.InvalidArgument*
// helper that maps to codes.InvalidArgument at the gRPC boundary.
func QueryNodesSafe(ctx context.Context, req *QueryNodesRequest) (*QueryNodesResponse, error) {
	for _, nid := range req.NodeIds {
		if _, err := uuid.Parse(nid); err != nil {
			return nil, errs.InvalidArgumentMalformedField(fmt.Errorf("unable to parse node IDs as UUIDs: %w", err))
		}
	}
	if _, err := keys.ParsePublicKey(req.OwnerIdentityPublicKey); err != nil {
		return nil, errs.InvalidArgumentMalformedKey(fmt.Errorf("failed to parse owner identity public key: %w", err))
	}
	return &QueryNodesResponse{}, nil
}
