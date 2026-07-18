// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire.
/// Marketplace / auction settlement pays out seller via the deprecated
/// 2300-gas payable(x).transfer(...) stipend. Fails for any Gnosis Safe
/// or smart-contract wallet beneficiary; C0142 cluster exemplar.
contract PayableTransferVuln {
    mapping(address => uint256) public proceeds;

    function settle(address seller, uint256 amt) external {
        proceeds[seller] -= amt;
        payable(seller).transfer(amt); // 2300-gas stipend, breaks for Safes
    }

    function refund(address buyer) external {
        uint256 amt = proceeds[buyer];
        proceeds[buyer] = 0;
        bool ok = payable(buyer).send(amt); // also 2300-gas, silent failure path
        require(ok, "refund failed");
    }
}
