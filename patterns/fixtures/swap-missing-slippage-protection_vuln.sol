// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRouter {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

/// @notice VULNERABLE FIXTURE — detector MUST fire.
/// Swap entrypoint passes amountOutMin = 0 and has no require on amountOut.
contract SwapNoSlippageVuln {
    IRouter public immutable router;

    constructor(address r) { router = IRouter(r); }

    function swapAndDeposit(
        uint256 amountIn,
        address[] calldata path
    ) external returns (uint256 out) {
        // VULN: amountOutMin hardcoded to 0, no post-swap slippage check
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            0,
            path,
            msg.sender,
            block.timestamp
        );
        out = amounts[amounts.length - 1];
    }

    function buyToken(uint256 amountIn, address[] calldata path)
        external
        returns (uint256 out)
    {
        // VULN: body invokes swapExact… but no require(...) on output
        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn, 0, path, msg.sender, block.timestamp
        );
        out = amounts[amounts.length - 1];
    }
}
