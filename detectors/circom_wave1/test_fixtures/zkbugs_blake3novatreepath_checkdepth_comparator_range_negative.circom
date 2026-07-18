pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template Blake3NovaTreePath_CheckDepth() {
    signal input depth;
    signal input leaf_depth;
    signal output is_parent;

    component n2b_depth = Num2Bits(8);
    n2b_depth.in <== depth;

    component n2b_leaf_depth = Num2Bits(8);
    n2b_leaf_depth.in <== leaf_depth;

    component check_parent = LessThan(8);
    check_parent.in[0] <== depth;
    check_parent.in[1] <== leaf_depth;

    component exceed_depth = GreaterEqThan(8);
    exceed_depth.in[0] <== depth;
    exceed_depth.in[1] <== leaf_depth;
    exceed_depth.out === 0;

    check_parent.out ==> is_parent;
}
