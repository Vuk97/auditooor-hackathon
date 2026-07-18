// Pattern 29 — POSITIVE fixture for
//   go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure
//
// RPC handler returns a bare fmt.Errorf wrapping a user-input parse
// failure. Mirrors the pre-fix shape behind Spark commit 86ee75a99f
// (PR #6420 — "Fix error classifications at RPC boundary").
package fixture

import (
	"context"
	"fmt"
)

// Stub proto/RPC types.
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

// BUG: bare fmt.Errorf wraps a uuid.Parse failure — should use
// errors.InvalidArgumentMalformedField(...) so the gRPC layer maps to
// codes.InvalidArgument.
func QueryNodes(ctx context.Context, req *QueryNodesRequest) (*QueryNodesResponse, error) {
	for _, nid := range req.NodeIds {
		if _, err := uuid.Parse(nid); err != nil {
			return nil, fmt.Errorf("unable to parse node IDs as UUIDs: %w", err)
		}
	}
	if _, err := keys.ParsePublicKey(req.OwnerIdentityPublicKey); err != nil {
		return nil, fmt.Errorf("failed to parse owner identity public key: %w", err)
	}
	return &QueryNodesResponse{}, nil
}
