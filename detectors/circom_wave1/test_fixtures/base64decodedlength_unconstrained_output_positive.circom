pragma circom 2.1.6;

template LessThan(n) {
    signal input in[2];
    signal output out;
    out <== 1;
}

template Base64DecodedLength(maxN) {
    signal input n;
    signal output decoded_len;

    signal q;
    signal r;
    signal r_lt_4;
    signal q_lt_max;

    3 * n - 4 * q - r === 0;
    component rBound = LessThan(3);
    rBound.in[0] <== r;
    rBound.in[1] <== 4;
    r_lt_4 <== rBound.out;
    r_lt_4 === 1;

    component qBound = LessThan(16);
    qBound.in[0] <== q;
    qBound.in[1] <== maxN;
    q_lt_max <== qBound.out;
    q_lt_max === 1;

    // Historical vulnerable shape: the intended constraint was commented out.
    // decoded_len <== q;
}

component main = Base64DecodedLength(1024);
