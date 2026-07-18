// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle { function getPrice() external view returns (uint256); }

contract LendingClean {
    IOracle public chainlink;
    IOracle public twap;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    function _min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; }
    function _max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; }

    // Clean: min() for collateral (underestimate), max() for debt (overestimate).
    function borrow(uint256 amount) external {
        uint256 pA = chainlink.getPrice();
        uint256 pB = twap.getPrice();
        uint256 collateralPrice = _min(pA, pB);
        uint256 debtPrice = _max(pA, pB);
        uint256 collateralValue = (collateral[msg.sender] * collateralPrice) / 1e18;
        uint256 debtValue = ((debt[msg.sender] + amount) * debtPrice) / 1e18;
        require(collateralValue * 80 / 100 >= debtValue, "undercollateralized");
        debt[msg.sender] += amount;
    }
}
