// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// FLAGGED: the bool return of `transfer` is discarded (bare statement-expression).
// A non-reverting ERC20 (returns false) makes this silently continue on failure.
contract UncheckedTransferSuspect {
    IERC20 public token;

    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    function pull(address from, address to, uint256 amount) external {
        token.transferFrom(from, to, amount);
    }
}
