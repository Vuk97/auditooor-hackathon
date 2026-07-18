// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STORAGE-MEDIATED def-use, UNGUARDED variant.
//   producer credit(): writes balances[acct] (state var X)
//   consumer payout():  reads  balances[acct] into a transfer, with NO
//                        require/assert/condition dominating the read of X.
//   The deepened engine's storage mode must surface a via:"storage"
//   DefUsePath  write@credit -> read@payout  with unguarded:true.
contract StorageUnguarded {
    mapping(address => uint256) public balances;
    address public sink;

    constructor(address _sink) {
        sink = _sink;
    }

    // PRODUCER: write-site of the storage var
    function credit(address acct, uint256 amount) external {
        balances[acct] += amount;
    }

    // CONSUMER: read-site of the storage var, value-dependent, UNGUARDED
    function payout(address acct) external {
        uint256 bal = balances[acct];
        payable(sink).transfer(bal);
    }
}
