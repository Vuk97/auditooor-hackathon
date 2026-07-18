pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

template IsEqual() {
    signal input in[2];
    signal output out;
}

template ItemAtIndex(n, bitLength) {
    signal input in[n];
    signal input index;
    signal output out;

    component lt = LessThan(bitLength);
    lt.in[0] <== index;
    lt.in[1] <== n;
    lt.out === 1;

    component eqs[n];
    var acc = 0;
    for (var i = 0; i < n; i++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== index;
        eqs[i].in[1] <== i;
        acc += eqs[i].out * in[i];
    }
    out <== acc;
}

template Sha256General(maxBlocks, maxBitLength) {
    signal input in[maxBitLength];
    signal input paddedInLength;
    signal output out[256];
    signal hashes[maxBlocks];
    signal inBlockIndex;

    inBlockIndex <-- (paddedInLength >> 9);
    paddedInLength === inBlockIndex * 512;

    component finalHash = ItemAtIndex(maxBlocks, 10);
    for (var i = 0; i < maxBlocks; i++) {
        finalHash.in[i] <== hashes[i];
    }
    finalHash.index <== inBlockIndex - 1;
    out[0] <== finalHash.out;
}
