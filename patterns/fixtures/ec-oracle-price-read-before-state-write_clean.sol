// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

// CLEAN: state updated first, price read after, no manipulation window
contract LendingVaultClean {
    IOracle public oracle;
    address public collateralToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _oracle, address _token) {
        oracle = IOracle(_oracle);
        collateralToken = _token;
    }

    // CLEAN: update state first, read price after — no sequencing gap
    function donateAndBorrow(uint256 donateAmount, uint256 borrowAmount) external {
        // Step 1: update state first (effects before interactions)
        collateral[msg.sender] += donateAmount;

        // Step 2: read price AFTER state is updated
        uint256 price = oracle.getPrice(collateralToken);

        // Step 3: health check using fresh price on updated state
        uint256 collateralValue = collateral[msg.sender] * price / 1e18;
        require(collateralValue >= borrowAmount * 2, "undercollateralized");

        debt[msg.sender] += borrowAmount;
    }
}
