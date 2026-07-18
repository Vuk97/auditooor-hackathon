pragma circom 2.1.6;

template SafeLowBits() {
    signal input leaf;
    signal output tag;

    component leafBits = Num2Bits(64);
    leafBits.in <== leaf;

    tag <== leafBits.out[0] + 2 * leafBits.out[1];
}

component main = SafeLowBits();
