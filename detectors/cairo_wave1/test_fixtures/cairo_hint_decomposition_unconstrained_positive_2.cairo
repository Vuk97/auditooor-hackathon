// Positive fixture: hint extracts bit LSB via modulo but no assert
// constrains that bit is 0 or 1, and that q * 2 + bit == value.
%builtins range_check

func extract_lsb{range_check_ptr}(value : felt) -> (bit : felt, quotient : felt) {
    alloc_locals;

    %{
        ids.quotient = ids.value // 2
        ids.bit = ids.value % 2
    %}

    // Missing constraint assertions:
    // assert bit * (1 - bit) = 0;  // bit is boolean
    // assert quotient * 2 + bit = value;  // reconstruction check

    return (bit=bit, quotient=quotient);
}
