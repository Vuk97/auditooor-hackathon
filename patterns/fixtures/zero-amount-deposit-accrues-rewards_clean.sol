// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: require(amount > 0) blocks zero-amount invocations from
// reaching the accrual / boost path.
contract BoostVaultClean {
    mapping(address => uint256) public shares;
    mapping(address => uint256) public boost;
    uint256 public totalShares;
    uint256 public rewardIndex;

    function proxyDeposit(address proxy, address to, uint128 amount) external {
        require(amount > 0, "zero amount");
        _accrue(to);
        shares[to] += amount;
        totalShares += amount;
        boost[to] += 1;
    }

    function _accrue(address user) internal {
        boost[user] = boost[user] + 1;
        rewardIndex += 1;
    }
}
