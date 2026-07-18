// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); }

// NOT a native stipend call: ERC20 transfer(to, amt) has TWO args. Must be SILENT.
contract TokenMover {
    IERC20 public token;
    function pay(address to, uint256 amt) external {
        token.transfer(to, amt);        // 2-arg ERC20 -> suppressed
        token.transferFrom(msg.sender, to, amt);
    }
}
