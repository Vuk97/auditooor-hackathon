// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// uniswap-v3-callback-msg-sender-not-verified detector. DO NOT DEPLOY.
///
/// Each AMM callback below is declared external/public and MOVES FUNDS
/// based on the untrusted amount0Delta / amount1Delta parameters, but
/// NONE of them verify msg.sender is the pool. An attacker can call any
/// of these directly with attacker-controlled deltas and drain the
/// contract's token balance or its victim's pre-approved allowance.

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract UniswapCallbackUnverifiedVuln {
    address public token0;
    address public token1;

    constructor(address _token0, address _token1) {
        token0 = _token0;
        token1 = _token1;
    }

    /// VULN: Uniswap V3 swap callback with no msg.sender check.
    /// Attacker calls directly with forged positive deltas — the router
    /// transfers token0/token1 to the attacker-controlled recipient.
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata /*data*/
    ) external {
        if (amount0Delta > 0) {
            IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
        }
        if (amount1Delta > 0) {
            IERC20(token1).transfer(msg.sender, uint256(amount1Delta));
        }
    }

    /// VULN: Uniswap V3 mint callback — no caller check.
    function uniswapV3MintCallback(
        uint256 amount0Owed,
        uint256 amount1Owed,
        bytes calldata /*data*/
    ) external {
        IERC20(token0).transfer(msg.sender, amount0Owed);
        IERC20(token1).transfer(msg.sender, amount1Owed);
    }

    /// VULN: Uniswap V2 / fork flash-swap callback with no gate.
    function uniswapV2Call(
        address /*sender*/,
        uint256 amount0,
        uint256 amount1,
        bytes calldata /*data*/
    ) external {
        if (amount0 > 0) IERC20(token0).transfer(msg.sender, amount0);
        if (amount1 > 0) IERC20(token1).transfer(msg.sender, amount1);
    }

    /// VULN: PancakeSwap V2 callback variant.
    function pancakeCall(
        address /*sender*/,
        uint256 amount0,
        uint256 amount1,
        bytes calldata /*data*/
    ) external {
        if (amount0 > 0) IERC20(token0).transfer(msg.sender, amount0);
        if (amount1 > 0) IERC20(token1).transfer(msg.sender, amount1);
    }

    /// VULN: Algebra / QuickSwap V3 callback alias.
    function algebraSwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata /*data*/
    ) external {
        if (amount0Delta > 0) IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) IERC20(token1).transfer(msg.sender, uint256(amount1Delta));
    }
}
