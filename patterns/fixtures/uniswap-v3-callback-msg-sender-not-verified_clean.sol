// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — secure reference for the
/// uniswap-v3-callback-msg-sender-not-verified detector. The detector
/// MUST NOT fire on this contract.
///
/// Every AMM callback below verifies that msg.sender is the expected
/// pool (either via a direct require, a stored pool address comparison,
/// a PoolAddress-library derivation, or an onlyPool modifier). The body
/// of each callback therefore contains at least one positive hit
/// against the pool-verify regex, so `body_not_contains_regex`
/// evaluates false and the detector does not fire.

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

interface IUniswapV3Pool {
    function token0() external view returns (address);
}

library PoolAddress {
    function computeAddress(address, bytes32) internal pure returns (address) {
        return address(0);
    }
}

contract UniswapCallbackVerifiedClean {
    address public pool;
    address public _pool;
    address public POOL;
    address public uniswapPool;
    address public token0;
    address public token1;

    modifier onlyPool() {
        require(msg.sender == pool, "not pool");
        _;
    }

    constructor(address _p, address _t0, address _t1) {
        pool = _p;
        _pool = _p;
        POOL = _p;
        uniswapPool = _p;
        token0 = _t0;
        token1 = _t1;
    }

    /// CLEAN: direct `require(msg.sender == pool, ...)` at top of body.
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata /*data*/
    ) external {
        require(msg.sender == pool, "not pool");
        if (amount0Delta > 0) IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) IERC20(token1).transfer(msg.sender, uint256(amount1Delta));
    }

    /// CLEAN: address(pool) form + IUniswapV3Pool cast token.
    function uniswapV3MintCallback(
        uint256 amount0Owed,
        uint256 amount1Owed,
        bytes calldata /*data*/
    ) external {
        require(msg.sender == address(pool), "not pool");
        // Reference the interface type so the positive IUniswapV3Pool regex
        // hit is explicit even in contracts that don't use a direct cast.
        address t0 = IUniswapV3Pool(pool).token0();
        t0;
        IERC20(token0).transfer(msg.sender, amount0Owed);
        IERC20(token1).transfer(msg.sender, amount1Owed);
    }

    /// CLEAN: onlyPool modifier form — the body text references onlyPool
    /// (the modifier name) even though the require lives in the modifier.
    function uniswapV2Call(
        address /*sender*/,
        uint256 amount0,
        uint256 amount1,
        bytes calldata /*data*/
    ) external onlyPool {
        if (amount0 > 0) IERC20(token0).transfer(msg.sender, amount0);
        if (amount1 > 0) IERC20(token1).transfer(msg.sender, amount1);
    }

    /// CLEAN: _pool underscored variable compared explicitly.
    function pancakeCall(
        address /*sender*/,
        uint256 amount0,
        uint256 amount1,
        bytes calldata /*data*/
    ) external {
        require(msg.sender == _pool, "not pool");
        if (amount0 > 0) IERC20(token0).transfer(msg.sender, amount0);
        if (amount1 > 0) IERC20(token1).transfer(msg.sender, amount1);
    }

    /// CLEAN: uniswapPool explicit variable name.
    function algebraSwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata /*data*/
    ) external {
        require(msg.sender == uniswapPool, "not pool");
        if (amount0Delta > 0) IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) IERC20(token1).transfer(msg.sender, uint256(amount1Delta));
    }

    /// CLEAN: PoolAddress library helper — canonical V3 periphery shape.
    /// The verification compares msg.sender directly against the
    /// deterministically-computed pool address, so the body matches the
    /// `msg.sender == PoolAddress` alternation of the detector regex.
    function swapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata /*data*/
    ) external {
        require(msg.sender == PoolAddress.computeAddress(address(this), bytes32(0)), "not pool");
        if (amount0Delta > 0) IERC20(token0).transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) IERC20(token1).transfer(msg.sender, uint256(amount1Delta));
    }
}
