pragma circom 2.1.9;

template ForceEqualIfEnabled() {
    signal input in[2];
    signal input enabled;
    (in[0] - in[1]) * enabled === 0;
}

template ZSwapV1() {
    signal input zAccountUtxoInNullifier;
    signal input zAccountUtxoInSpendPrivKey;
    signal input zAccountUtxoInHasherOut;
    signal output zAccountUtxoInNullifierHasherOut;

    zAccountUtxoInNullifierHasherOut <== zAccountUtxoInHasherOut;

    component zAccountUtxoInNullifierHasherProver = ForceEqualIfEnabled();
    zAccountUtxoInNullifierHasherProver.in[0] <== zAccountUtxoInNullifier;
    zAccountUtxoInNullifierHasherProver.in[1] <== zAccountUtxoInNullifierHasherOut;
    zAccountUtxoInNullifierHasherProver.enabled <== zAccountUtxoInSpendPrivKey;
}

component main = ZSwapV1();
