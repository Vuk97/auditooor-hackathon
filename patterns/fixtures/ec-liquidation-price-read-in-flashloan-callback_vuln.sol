// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILending {
    function liquidate(address borrower, uint256 amount) external;
    function getPrice() external view returns (uint256);
}

// VULN: liquidation called inside flashloan callback, price read post-manipulation
// Loss ref: Radiant Capital ~$4.5M, Jan 2024
// https://rekt.news/radiant-capital-rekt/
contract FlashloanAttackerVuln {
    ILending public lending;

    constructor(address _lending) { lending = ILending(_lending); }

    // VULN: this is a flashloan callback that both reads price and calls liquidate
    function uniswapV2Call(address, uint256, uint256, bytes calldata data) external {
        address borrower = abi.decode(data, (address));

        // Price has already been manipulated by the flashloan setup
        uint256 price = lending.getPrice(); // reads manipulated price

        // Liquidation executes against the manipulated price
        uint256 amount = 100e18;
        lending.liquidate(borrower, amount); // over-rewards attacker
    }
}
