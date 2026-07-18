// Pattern 23 — POSITIVE fixture for
//   go.spark.grpc.default_service_config_last_write_wins
//
// dialWithRetryAndLB calls grpc.WithDefaultServiceConfig TWICE on the
// same DialOption slice. grpc-go's setter is a single-pointer overwrite,
// so the earlier retry-policy is silently dropped — only the LB policy
// survives.
//
// Mirrors SP-6314 (``51dc21a3ce``) on buildonspark/spark.
package fixture

import (
	"context"
)

type ClientConn struct{}

type DialOption interface{}

func WithDefaultServiceConfig(s string) DialOption { return nil }
func grpcWithDefaultServiceConfig(s string) DialOption { return nil }

type grpcModule struct{}

func (g grpcModule) WithDefaultServiceConfig(s string) DialOption { return nil }

var grpc = grpcModule{}

func dialOpts() []DialOption { return nil }

func DialContext(ctx context.Context, target string, opts ...DialOption) (*ClientConn, error) {
	return &ClientConn{}, nil
}

const retryPolicyJSON = `{"retryPolicy":{...}}`
const lbPolicyJSON = `{"loadBalancingConfig":[{"round_robin":{}}]}`

// dialWithRetryAndLB — TWO calls on the same DialOption chain. Bug shape.
func dialWithRetryAndLB(ctx context.Context, target string) (*ClientConn, error) {
	opts := []DialOption{
		grpc.WithDefaultServiceConfig(retryPolicyJSON),
		grpc.WithDefaultServiceConfig(lbPolicyJSON),
	}
	return DialContext(ctx, target, opts...)
}

// dialChainAppend — same shape via append. Bug shape.
func dialChainAppend(ctx context.Context, target string) (*ClientConn, error) {
	var opts []DialOption
	opts = append(opts, grpc.WithDefaultServiceConfig(retryPolicyJSON))
	opts = append(opts, grpc.WithDefaultServiceConfig(lbPolicyJSON))
	return DialContext(ctx, target, opts...)
}
