// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint256 a0Out, uint256 a1Out, address to, bytes calldata) external;
}

interface IRouter {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin,
        address[] calldata path, address to, uint256 deadline)
        external returns (uint256[] memory);
}

contract AgentTaxVuln {
    IRouter public router;
    IPair public pair;
    address public tokenIn;
    address public tokenOut;

    // VULN: minOut is computed from live reserves inside the same tx.
    function dcaSell(uint256 amountIn) external {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 amountOut = (amountIn * r1) / (r0 + amountIn);
        uint256 minOut = (amountOut * 995) / 1000;
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        router.swapExactTokensForTokens(amountIn, minOut, path, address(this), block.timestamp);
    }
}
