// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IUniswapV2Router {
    function addLiquidityETH(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external payable returns (uint256, uint256, uint256);
}

contract LauncherVuln {
    IUniswapV2Router public router;
    address public token;

    function launch(uint256 amt) external payable {
        // VULN: no reserve sanity check
        router.addLiquidityETH{value: msg.value}(token, amt, 0, 0, msg.sender, block.timestamp);
    }
}
