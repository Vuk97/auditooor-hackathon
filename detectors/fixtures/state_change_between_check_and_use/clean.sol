// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenStateChangeClean {
    function safeTransfer(address to, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ClaimSyncBeforeClaimedCheckClean {
    ITokenStateChangeClean public rewardToken;
    mapping(bytes32 => bool) public claimed;
    mapping(address => uint256) public rewards;

    function claim(bytes32 claimId, uint256 amount) external {
        _syncClaim(claimId);

        require(!claimed[claimId], "claimed");

        claimed[claimId] = true;
        rewards[msg.sender] += amount;
        rewardToken.safeTransfer(msg.sender, amount);
    }

    function _syncClaim(bytes32 claimId) internal view {
        claimId;
    }
}

contract OrderFillRechecksAfterSettlementClean {
    struct Order {
        address maker;
        bool open;
        uint256 remaining;
    }

    mapping(bytes32 => Order) public orders;
    mapping(address => uint256) public proceeds;

    function fill(bytes32 orderId, uint256 amount) external {
        require(orders[orderId].open, "not open");

        _settleOrder(orderId, amount);

        uint256 remainingAfter = orders[orderId].remaining;
        require(orders[orderId].open && remainingAfter >= amount, "not fillable after settle");

        proceeds[orders[orderId].maker] += amount;
        orders[orderId].remaining = remainingAfter - amount;
    }

    function _settleOrder(bytes32 orderId, uint256 amount) internal {
        if (amount > orders[orderId].remaining) {
            orders[orderId].open = false;
        }
    }
}

contract LendingAccrueBeforeHealthCheckClean {
    ITokenStateChangeClean public collateralToken;
    mapping(address => uint256) public health;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function withdraw(uint256 amount) external {
        accrueInterest(msg.sender);

        uint256 healthAfter = health[msg.sender];
        require(healthAfter >= 1e18, "unhealthy after accrue");

        collateral[msg.sender] -= amount;
        collateralToken.safeTransfer(msg.sender, amount);
    }

    function accrueInterest(address user) internal {
        debt[user] += 1e18;
        health[user] -= 1;
    }
}
