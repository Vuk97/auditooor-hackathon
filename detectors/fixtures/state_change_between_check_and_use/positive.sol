// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenStateChangePositive {
    function safeTransfer(address to, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ClaimSyncAfterClaimedCheckPositive {
    ITokenStateChangePositive public rewardToken;
    mapping(bytes32 => bool) public claimed;
    mapping(address => uint256) public rewards;

    function claim(bytes32 claimId, uint256 amount) external {
        require(!claimed[claimId], "claimed");

        _syncClaim(claimId);

        rewards[msg.sender] += amount;
        rewardToken.safeTransfer(msg.sender, amount);
    }

    function _syncClaim(bytes32 claimId) internal {
        claimed[claimId] = true;
    }
}

contract OrderFillAfterOpenCheckPositive {
    struct Order {
        address maker;
        bool open;
        uint256 remaining;
    }

    mapping(bytes32 => Order) public orders;
    mapping(address => uint256) public proceeds;

    function fill(bytes32 orderId, uint256 amount) external {
        require(orders[orderId].open && orders[orderId].remaining >= amount, "not fillable");

        _settleOrder(orderId, amount);

        proceeds[orders[orderId].maker] += amount;
        orders[orderId].remaining -= amount;
    }

    function _settleOrder(bytes32 orderId, uint256 amount) internal {
        if (amount >= orders[orderId].remaining) {
            orders[orderId].open = false;
        }
    }
}

contract LendingAccrueAfterHealthCheckPositive {
    ITokenStateChangePositive public collateralToken;
    mapping(address => uint256) public health;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function withdraw(uint256 amount) external {
        require(health[msg.sender] >= 1e18, "unhealthy");

        accrueInterest(msg.sender);

        collateral[msg.sender] -= amount;
        collateralToken.safeTransfer(msg.sender, amount);
    }

    function accrueInterest(address user) internal {
        debt[user] += 1e18;
        health[user] -= 1;
    }
}
