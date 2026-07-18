package consume

// G9 fixture - go.consensus.decoded_value_consumed_unchecked_type_nil.
// Each function models one arm / guard of the predicate. Comments name the
// expected detector verdict (FIRE <arm> / CLEAN <why>). These are parsed by the
// regex extractor, not compiled - the shapes are what matter.

// FIRE (arm A): codec.Unmarshal into &val, then a single-return val.(T)
// assertion (no comma-ok) -> panics on the wrong dynamic type = DoS.
func laxUnmarshalAssert(bz []byte) error {
	var val Wrapper
	codec.Unmarshal(bz, &val)
	inner := val.(InnerI)
	return inner.Do()
}

// FIRE (arm B): an Any consumed via GetCachedValue() and single-return
// .(AccountI)-asserted - attacker controls the packed concrete type.
func laxCachedAssert(any *codectypes.Any) error {
	acc := any.GetCachedValue().(AccountI)
	return acc.Validate()
}

// FIRE (arm B, field-deref): GetCachedValue() result field-dereferenced with no
// checked/comma-ok variant.
func laxCachedFieldDeref(any *codectypes.Any) uint64 {
	return any.GetCachedValue().Height
}

// FIRE (arm C): decoded POINTER field-deref BEFORE any nil-check (a strict
// decode-taint-gated subset of Pattern 35). `var target *Header` is nil-able.
func laxPtrDeref(bz []byte) (uint64, error) {
	var target *Header
	proto.Unmarshal(bz, &target)
	return target.Height, nil
}

// FIRE (arm C, pointer param): the decode target is a `*T` PARAMETER - nil-able,
// so the pre-nil-check field-deref is a genuine nil-deref.
func ptrParamDeref(bz []byte, target *Header) uint64 {
	proto.Unmarshal(bz, &target)
	return target.Height
}

// CLEAN (arm C precision): a VALUE-struct decode target can NEVER be nil. The
// idiom `var dec T; json.Unmarshal(data, &dec); use dec.Field` captures `dec`
// via `&dec`, but `dec` is a value struct, so the field-deref is sound - it must
// stay SILENT (the optimism 29/36, polygon 96/123 arm-C value-target FP class).
// Contrast laxPtrDeref, whose target `var target *Header` is a nil-able pointer.
func valueTargetFieldDeref(bz []byte) uint64 {
	var dec Header
	json.Unmarshal(bz, &dec)
	return dec.Height
}

// CLEAN: comma-ok form guards the assertion (the checked variant).
func okAssert(any *codectypes.Any) error {
	acc, ok := any.GetCachedValue().(AccountI)
	if !ok {
		return ErrBadType
	}
	return acc.Validate()
}

// CLEAN: a type-switch consumes the decoded value type-safely.
func switchAssert(any *codectypes.Any) error {
	switch v := any.GetCachedValue().(type) {
	case AccountI:
		return v.Validate()
	default:
		return ErrBadType
	}
}

// CLEAN (arm C guard): decoded pointer nil-checked before the field deref.
func nilGuardedDeref(bz []byte) (uint64, error) {
	var target *Header
	if err := proto.Unmarshal(bz, &target); err != nil {
		return 0, err
	}
	if target == nil {
		return 0, ErrNil
	}
	return target.Height, nil
}

// CLEAN: err-checked UnpackAny validates the target -> suppressed.
func errCheckedUnpack(cdc Codec, any *Any) error {
	var acc AccountI
	if err := cdc.UnpackAny(any, &acc); err != nil {
		return err
	}
	return acc.Validate()
}

// CLEAN: NO decode source in the body - a bare v.(T) must NOT fire (asserts R9
// does not regress into Pattern-35 breadth).
func noDecodeBareAssert(v interface{}) error {
	x := v.(AccountI)
	return x.Validate()
}
