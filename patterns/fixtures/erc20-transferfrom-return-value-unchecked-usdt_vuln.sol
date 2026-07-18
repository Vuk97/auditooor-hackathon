// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// @notice VULNERABLE FIXTURE — detector MUST fire.
///
/// USDT-style protocol-level bug shape:
/// - `token` is a canonical storage variable (IERC20 token)
/// - deposit / withdraw call bare transferFrom / transfer on that handle
/// - no wrapper library, no require on the bool return, no permit flow
///
/// Against USDT (returns no bool) or against a token that returns false
/// on failure without reverting, the internal `balances` ledger silently
/// desyncs from the real token ledger.
contract UsdtUncheckedVuln {
    IERC20 public immutable token;
    IERC20 public immutable asset = IERC20(address(0));
    mapping(address => uint256) public balances;

    constructor(address t) { token = IERC20(t); }

    // Vulnerable: bare transferFrom on storage `token`. Return discarded.
    function deposit(uint256 amt) external {
        token.transferFrom(msg.sender, address(this), amt);
        balances[msg.sender] += amt;
    }

    // Vulnerable: bare transfer on storage `token`.
    function withdraw(uint256 amt) external {
        balances[msg.sender] -= amt;
        token.transfer(msg.sender, amt);
    }

    // Additional vulnerable surface on `asset`-named storage var.
    function skim(address to, uint256 amt) external {
        asset.transfer(to, amt);
    }
}
