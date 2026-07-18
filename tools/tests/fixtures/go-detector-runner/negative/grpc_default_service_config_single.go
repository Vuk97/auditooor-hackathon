// Pattern 23 — NEGATIVE fixture.
//
// dialWithSingleConfig calls WithDefaultServiceConfig EXACTLY ONCE with a
// merged retry+LB policy JSON. Detector must NOT fire.
//
// Mirrors the post-fix shape introduced in SP-6314.
package fixturen

import (
	"context"
)

type ClientConnN struct{}

type DialOptionN interface{}

type grpcModuleN struct{}

func (g grpcModuleN) WithDefaultServiceConfig(s string) DialOptionN { return nil }

var grpcN = grpcModuleN{}

func DialContextN(ctx context.Context, target string, opts ...DialOptionN) (*ClientConnN, error) {
	return &ClientConnN{}, nil
}

const mergedPolicyJSON = `{"retryPolicy":{...},"loadBalancingConfig":[{"round_robin":{}}]}`

// dialWithSingleConfig — defended shape: one call only.
func dialWithSingleConfig(ctx context.Context, target string) (*ClientConnN, error) {
	opts := []DialOptionN{
		grpcN.WithDefaultServiceConfig(mergedPolicyJSON),
	}
	return DialContextN(ctx, target, opts...)
}
