// SPDX-License-Identifier: MIT
// Fixture: missing-deadline-param-on-swap-external — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

/// @notice Minimal reproduction of cluster C0118. DO NOT DEPLOY.
///
/// `swap` and `exchange` are user-facing entrypoints that take an
/// amountIn argument but never accept or check a deadline anywhere in
/// the body. A mempool-held tx can execute minutes or hours later at
/// an adverse price.
interface IPool {
    function doSwap(uint256 amountIn, uint256 minOut, address to) external returns (uint256);
}

contract SwapNoDeadlineVuln {
    IPool public pool;

    constructor(IPool _pool) {
        pool = _pool;
    }

    // VULN: `swap` accepts a uint256 amountIn but has no deadline /
    // expiry / block.timestamp check anywhere in its body.
    function swap(uint256 amountIn, uint256 minOut) external returns (uint256 out) {
        out = pool.doSwap(amountIn, minOut, msg.sender);
    }

    // VULN: `exchange` same shape.
    function exchange(uint256 amountIn, uint256 minOut, address to) external returns (uint256 out) {
        out = pool.doSwap(amountIn, minOut, to);
    }

    // VULN: `buyToken` — alternate anchor name in the pattern.
    function buyToken(uint256 amountIn) external returns (uint256 out) {
        out = pool.doSwap(amountIn, 0, msg.sender);
    }
}
