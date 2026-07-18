// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STORAGE-MEDIATED def-use, GUARDED variant (mutation pair of storage_unguarded).
//   Same producer/consumer storage flow, BUT the consumer payout() has a
//   require() dominating the read of the storage var X. The deepened engine's
//   storage mode must surface the SAME via:"storage" path but with
//   unguarded:false and a populated guard_nodes list - the guard is the ONLY
//   difference, so the unguarded flag flips. assert(true) cannot do that.
contract StorageGuarded {
    mapping(address => uint256) public balances;
    uint256 public cap;
    address public sink;

    constructor(address _sink, uint256 _cap) {
        sink = _sink;
        cap = _cap;
    }

    // PRODUCER: write-site of the storage var
    function credit(address acct, uint256 amount) external {
        balances[acct] += amount;
    }

    // CONSUMER: read-site of the storage var, GUARDED by require over balances
    function payout(address acct) external {
        require(balances[acct] <= cap, "over cap");
        uint256 bal = balances[acct];
        payable(sink).transfer(bal);
    }
}
