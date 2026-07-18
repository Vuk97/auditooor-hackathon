// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

// VULN: price read BEFORE state write — oracle sequencing bug
// Loss ref: Euler Finance ~$197M, March 2023
// https://rekt.news/euler-rekt/
contract LendingVaultVuln {
    IOracle public oracle;
    address public collateralToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _oracle, address _token) {
        oracle = IOracle(_oracle);
        collateralToken = _token;
    }

    // VULN: reads price before updating collateral state
    // An attacker can inflate the price BETWEEN the read and the state update
    function donateAndBorrow(uint256 donateAmount, uint256 borrowAmount) external {
        // Step 1: read price (before state update)
        uint256 price = oracle.getPrice(collateralToken);

        // Step 2: update state
        collateral[msg.sender] += donateAmount;

        // Step 3: compute health using stale pre-update price snapshot
        uint256 collateralValue = collateral[msg.sender] * price / 1e18;
        require(collateralValue >= borrowAmount * 2, "undercollateralized");

        debt[msg.sender] += borrowAmount;
    }
}
