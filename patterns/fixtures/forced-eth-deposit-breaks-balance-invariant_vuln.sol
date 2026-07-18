// SPDX-License-Identifier: MIT
// Fixture: forced-eth-deposit-breaks-balance-invariant — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract VulnPool {
    uint256 public trackedEth;

    receive() external payable {
        trackedEth += msg.value;
    }

    // VULN: invariant `address(this).balance == trackedEth` can be
    // broken by selfdestruct(pool) — ETH arrives without triggering
    // receive(), trackedEth stays stale, every call to swap() reverts.
    function swap() external {
        require(address(this).balance == trackedEth, "balance invariant");
        // ... swap logic ...
    }

    // VULN: same invariant enforced via assert — attacker's forced
    // donation freezes withdrawals too.
    function withdraw(uint256 amount) external {
        assert(address(this).balance == trackedEth);
        trackedEth -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "xfer");
    }
}
