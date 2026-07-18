// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IPool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
}

contract ProtocolDoesntProperlyHandleAavePoolChangesPositive {
    IERC20 public immutable asset;
    address public owner;
    address public aavePool;
    bool public isDepositTokenAdded;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(IERC20 asset_, address pool_) {
        owner = msg.sender;
        asset = asset_;
        aavePool = pool_;
    }

    function addDepositPool() external onlyOwner {
        require(!isDepositTokenAdded, "already added");
        asset.approve(aavePool, type(uint256).max);
        isDepositTokenAdded = true;
    }

    function setAavePool(address value_) external onlyOwner {
        require(value_ != address(0), "invalid pool");
        aavePool = value_;
    }

    function stake(uint256 amount) external {
        IPool(aavePool).supply(address(asset), amount, address(this), 0);
    }
}
