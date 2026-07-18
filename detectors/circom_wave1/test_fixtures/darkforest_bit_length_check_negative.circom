pragma circom 2.0.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template RangeProof(bits, max_abs_value) {
    signal input in;
    signal shifted;
    signal doubledMax;

    shifted <== max_abs_value + in;
    doubledMax <== 2 * max_abs_value;

    component shiftedBits = Num2Bits(bits);
    shiftedBits.in <== shifted;

    component doubledMaxBits = Num2Bits(bits);
    doubledMaxBits.in <== doubledMax;

    component lowerBound = LessThan(bits);
    component upperBound = LessThan(bits);

    lowerBound.in[0] <== shifted;
    lowerBound.in[1] <== 0;
    lowerBound.out === 0;

    upperBound.in[0] <== doubledMax;
    upperBound.in[1] <== shifted;
    upperBound.out === 0;
}

component main = RangeProof(9, 255);
