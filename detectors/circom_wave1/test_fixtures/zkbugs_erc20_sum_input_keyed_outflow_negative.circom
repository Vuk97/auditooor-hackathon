pragma circom 2.0.0;

template IsEqual() {
    signal input in[2];
    signal output out;
    out <-- in[0] == in[1] ? 1 : 0;
    out * (out - 1) === 0;
    out * (in[0] - in[1]) === 0;
}

template ERC20Sum(n) {
    signal input addr;
    signal input token_addr[n];
    signal input amount[n];
    signal output out;
    signal include[n];
    signal running[n + 1];

    running[0] <== 0;
    for (var i = 0; i < n; i++) {
        include[i] <-- token_addr[i] == addr ? 1 : 0;
        running[i + 1] <== running[i] + include[i] * amount[i];
    }
    out <== running[n];
}

template ZkTransactionLikeFixed(nIn, nOut) {
    signal input spending_note_token_addr[nIn];
    signal input spending_note_amount[nIn];
    signal input output_note_token_addr[nOut];
    signal input output_note_amount[nOut];

    component output_token_addr_in_inputs[nOut][nIn];
    signal seen[nOut];

    for (var j = 0; j < nOut; j++) {
        seen[j] <== 0;
        for (var i = 0; i < nIn; i++) {
            output_token_addr_in_inputs[j][i] = IsEqual();
            output_token_addr_in_inputs[j][i].in[0] <== output_note_token_addr[j];
            output_token_addr_in_inputs[j][i].in[1] <== spending_note_token_addr[i];
            seen[j] <== seen[j] + output_token_addr_in_inputs[j][i].out;
        }
        seen[j] === 1;
    }

    component inflow_erc20[nIn] = ERC20Sum(nIn);
    component outflow_erc20[nIn] = ERC20Sum(nOut);

    for (var i = 0; i < nIn; i++) {
        inflow_erc20[i].addr <== spending_note_token_addr[i];
        outflow_erc20[i].addr <== spending_note_token_addr[i];

        for (var j = 0; j < nIn; j++) {
            inflow_erc20[i].token_addr[j] <== spending_note_token_addr[j];
            inflow_erc20[i].amount[j] <== spending_note_amount[j];
        }
        for (var j = 0; j < nOut; j++) {
            outflow_erc20[i].token_addr[j] <== output_note_token_addr[j];
            outflow_erc20[i].amount[j] <== output_note_amount[j];
        }

        inflow_erc20[i].out === outflow_erc20[i].out;
    }
}

component main = ZkTransactionLikeFixed(2, 2);
