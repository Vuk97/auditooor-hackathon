// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: AaveBoost-style proxyDeposit. No amount > 0 check, so each
// zero-amount call still updates the boost / index storage and credits
// shares. An attacker loops the call to farm boost balance.
contract BoostVaultVuln {
    mapping(address => uint256) public shares;
    mapping(address => uint256) public boost;
    uint256 public totalShares;
    uint256 public rewardIndex;

    function proxyDeposit(address proxy, address to, uint128 amount) external {
        // No require(amount > 0) — the accrual path still runs.
        _accrue(to);
        shares[to] += amount;
        totalShares += amount;
        boost[to] += 1;  // monotonic boost counter — can be farmed
    }

    function _accrue(address user) internal {
        boost[user] = boost[user] + 1;
        rewardIndex += 1;
    }
}
