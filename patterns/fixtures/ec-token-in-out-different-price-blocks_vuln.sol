// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}
interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// VULN: tokenIn and tokenOut priced by separate oracle calls with transfer between
// Loss ref: Zunami Protocol ~$2.1M, August 2023
// https://rekt.news/zunami-protocol-rekt/
contract SwapVuln {
    IOracle public oracle;

    constructor(address _oracle) { oracle = IOracle(_oracle); }

    // VULN: reads priceIn, executes transfer (which can trigger hooks), reads priceOut
    function swap(address tokenIn, address tokenOut, uint256 amountIn) external {
        uint256 priceIn = oracle.getPrice(tokenIn);  // read 1

        // External transfer — can trigger FoT hook, re-entry, or oracle move
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        uint256 priceOut = oracle.getPrice(tokenOut); // read 2 — price may have moved

        uint256 amountOut = amountIn * priceIn / priceOut;
        IERC20(tokenOut).transfer(msg.sender, amountOut);
    }
}
