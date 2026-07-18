// SPDX-License-Identifier: MIT
// Fixture: missing-deadline-param-on-swap-external — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IPool {
    function doSwap(uint256 amountIn, uint256 minOut, address to, uint256 deadline)
        external
        returns (uint256);
}

/// @notice Clean version: every swap-surface entrypoint accepts a
/// deadline parameter and enforces `block.timestamp <= deadline`. The
/// `deadline` token in the body satisfies the pattern's
/// body_not_contains_regex negative guard and the detector stays
/// silent.
contract SwapNoDeadlineClean {
    IPool public pool;

    constructor(IPool _pool) {
        pool = _pool;
    }

    // CLEAN: named `deadline` parameter, require check, value forwarded
    // into the pool call. `deadline` token present in the body.
    function swap(uint256 amountIn, uint256 minOut, uint256 deadline)
        external
        returns (uint256 out)
    {
        require(block.timestamp <= deadline, "expired");
        out = pool.doSwap(amountIn, minOut, msg.sender, deadline);
    }

    // CLEAN: alternate expiry-named parameter also satisfies the
    // negative guard because `expiry` is in the regex.
    function exchange(uint256 amountIn, uint256 minOut, address to, uint256 expiry)
        external
        returns (uint256 out)
    {
        require(block.timestamp <= expiry, "expired");
        out = pool.doSwap(amountIn, minOut, to, expiry);
    }

    // CLEAN: validUntil name still satisfies the negative guard.
    function buyToken(uint256 amountIn, uint256 validUntil) external returns (uint256 out) {
        require(block.timestamp <= validUntil, "expired");
        out = pool.doSwap(amountIn, 0, msg.sender, validUntil);
    }
}
