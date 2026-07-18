pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template EpochKeyLite() {
    signal input epochKeyNonce;
    signal output validNonce;

    var EPOCH_KEY_NONCE_PER_EPOCH = 3;

    component nonceBits = Num2Bits(8);
    nonceBits.in <== epochKeyNonce;

    component nonceLessThan = LessThan(8);
    nonceLessThan.in[0] <== epochKeyNonce;
    nonceLessThan.in[1] <== EPOCH_KEY_NONCE_PER_EPOCH;
    nonceLessThan.out === validNonce;
}
