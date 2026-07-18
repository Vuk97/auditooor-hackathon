// Pattern 1 — NEGATIVE fixture (proto-enum dispatch).
//
// Models the Spark FP shape (`hashVariant == pb.HashVariant_HASH_VARIANT_V2`)
// at common/proof.go:14, deposit_handler.go:542/572, and
// internal_deposit_handler.go:438. The variable name happens to contain
// "Hash", which trips the txid_eq lexical predicate, but the RHS is a
// generated proto-enum constant (package.Type_VARIANT shape with all-caps
// variant tail) and the comparison is dispatch, not a missing-spend bug.
// The detector must suppress this.
package fixture_proto_enum

// `pb` mimics the generated protobuf package — protoc emits constants of the
// form `pb.<EnumType>_<VARIANT>` with an ALL-CAPS variant tail.
type pbPkg struct {
	HashVariant_HASH_VARIANT_V1 int
	HashVariant_HASH_VARIANT_V2 int
}

var pb = pbPkg{HashVariant_HASH_VARIANT_V1: 0, HashVariant_HASH_VARIANT_V2: 1}

// Param `hashVariant` matches PARAM_TXID_RE; the body uses `==` against a
// proto-enum constant `pb.HashVariant_HASH_VARIANT_V2`. No spend verifier
// is called. The detector should NOT fire — this is enum-dispatch.
func DispatchOnHashVariant(hashVariant int) string {
	if hashVariant == pb.HashVariant_HASH_VARIANT_V2 {
		return "v2"
	}
	return "v1"
}

// A second flavor with reversed sides — the suppression must catch this too.
func DispatchOnHashVariantRev(hashVariant int) string {
	if pb.HashVariant_HASH_VARIANT_V2 == hashVariant {
		return "v2-rev"
	}
	return "v1-rev"
}
