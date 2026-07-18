// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

// MUTATION-NON-VACUITY base: exactly ONE bare transfer (unconsumed bool return)
// -> FLAGGED. The mutation wraps the call in `require(...)` (consuming the
// return), which must flip FLAGGED -> clean. This proves the oracle keys on
// return-value CONSUMPTION, not on the mere presence of a transfer call.
contract UncheckedReturnMutationBase {
    IERC20 public token;

    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
