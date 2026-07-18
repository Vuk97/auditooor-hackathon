// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DonateReserveClean {
    mapping(address => uint256) public collateralBalances;
    uint256 public reserves;
    uint256 public protocolReserve;

    function donateToReserves(uint256 amount) external {
        require(amount > 0, "amount=0");
        collateralBalances[msg.sender] -= amount;
        reserves += amount;
        checkLiquidity(msg.sender);
    }

    function reduceCollateral(uint256 amount) external {
        collateralBalances[msg.sender] -= amount;
        protocolReserve += amount;
        requireAccountStatusCheck(msg.sender);
    }

    function contributeToReserve(uint256 amount) external {
        collateralBalances[msg.sender] -= amount;
        reserves += amount;
        require(_isHealthy(msg.sender), "unhealthy");
    }

    function checkLiquidity(address user) internal view {
        require(collateralBalances[user] >= 1, "unhealthy");
    }

    function requireAccountStatusCheck(address user) internal view {
        require(collateralBalances[user] >= 1, "bad status");
    }

    function _isHealthy(address user) internal view returns (bool) {
        return collateralBalances[user] >= 1;
    }
}
