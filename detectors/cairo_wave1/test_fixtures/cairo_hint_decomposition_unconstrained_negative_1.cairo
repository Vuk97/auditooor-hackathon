// Negative fixture: hint decomposes value AND assertion follows that
// constrains the reconstruction. Properly verified decomposition.
%builtins range_check

func split_felt_safe{range_check_ptr}(value : felt) -> (low : felt, high : felt) {
    alloc_locals;

    %{
        ids.low = ids.value & ((1 << 128) - 1)
        ids.high = ids.value >> 128
    %}

    // Constraint: verify reconstruction (prover must supply correct low/high)
    assert low + high * 340282366920938463463374607431768211456 = value;

    return (low=low, high=high);
}
