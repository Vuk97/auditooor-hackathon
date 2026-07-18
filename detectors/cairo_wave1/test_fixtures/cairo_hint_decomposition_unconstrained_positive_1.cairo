// Positive fixture: hint decomposes `value` into high/low limbs but no
// assert constrains that high * 2^128 + low == value.
%builtins range_check

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_nn

func split_felt{range_check_ptr}(value : felt) -> (low : felt, high : felt) {
    alloc_locals;

    // BUG: hint decomposes value but no assertion follows
    %{
        ids.low = ids.value & ((1 << 128) - 1)
        ids.high = ids.value >> 128
    %}

    // Missing: assert ids.low + ids.high * 2**128 = ids.value;
    // The prover can supply arbitrary low/high without the STARK proof verifying them.

    return (low=low, high=high);
}
