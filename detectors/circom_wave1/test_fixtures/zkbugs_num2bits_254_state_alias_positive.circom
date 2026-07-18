pragma circom 2.1.6;

template BlacklistLeafState() {
    signal input blacklistLeaf;
    signal output blacklistState;

    component leafBits = Num2Bits(254);
    leafBits.in <== blacklistLeaf;

    blacklistState <== leafBits.out[251] + 2 * leafBits.out[252] + 4 * leafBits.out[253];
}

component main = BlacklistLeafState();
