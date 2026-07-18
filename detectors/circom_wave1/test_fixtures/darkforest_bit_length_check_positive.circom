pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

// Reduced from Dark Forest v0.3 RangeProof.
template RangeProof(bits, max_abs_value) {
    signal input in;

    component lowerBound = LessThan(bits);
    component upperBound = LessThan(bits);

    lowerBound.in[0] <== max_abs_value + in;
    lowerBound.in[1] <== 0;
    lowerBound.out === 0;

    upperBound.in[0] <== 2 * max_abs_value;
    upperBound.in[1] <== max_abs_value + in;
    upperBound.out === 0;
}

component main = RangeProof(9, 255);
