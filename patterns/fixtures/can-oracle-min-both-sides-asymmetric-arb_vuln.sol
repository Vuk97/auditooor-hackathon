// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle { function getPrice() external view returns (uint256); }

contract LendingVuln {
    IOracle public chainlink;
    IOracle public twap;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    // BUG: uses min() on BOTH collateral and debt side — symmetric bias.
    function borrow(uint256 amount) external {
        uint256 price = _min(chainlink.getPrice(), twap.getPrice());
        uint256 collateralValue = (collateral[msg.sender] * price) / 1e18;
        uint256 debtValue = (debt[msg.sender] + amount) * price / 1e18;
        require(collateralValue * 80 / 100 >= debtValue, "undercollateralized");
        debt[msg.sender] += amount;
    }
}
