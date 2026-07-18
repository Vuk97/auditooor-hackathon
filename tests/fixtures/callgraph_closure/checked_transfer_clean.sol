// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

// NOT FLAGGED: the bool return of `transfer` is consumed by a require guard.
contract CheckedTransferClean {
    IERC20 public token;

    function pay(address to, uint256 amount) external {
        require(token.transfer(to, amount), "transfer failed");
    }
}
