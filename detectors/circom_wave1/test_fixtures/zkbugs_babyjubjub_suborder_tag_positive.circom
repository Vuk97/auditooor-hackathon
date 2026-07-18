pragma circom 2.1.6;

include "circomlib/comparators.circom";

template BabyJubJubSubOrderTag(isActive) {
    signal input in;
    signal output tagged;

    var suborder = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    component n2b = LessThan(251);
    n2b.in[0] <== in;
    n2b.in[1] <== suborder;

    tagged <== in;
}

component main = BabyJubJubSubOrderTag(1);
