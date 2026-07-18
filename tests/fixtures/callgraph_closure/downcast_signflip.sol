// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (b): a SIGN-FLIP cast int256 -> uint256 on a value-moving `balance`
// (downcast_suspect=TRUE, kind=sign-flip). A negative int256 is re-interpreted as
// a huge positive uint256 - the value is silently changed by the conversion.
contract DowncastSignFlip {
    mapping(address => uint256) public balances;

    // SIGN-FLIP: int256 value cast to uint256 (a negative becomes huge positive). // DOWNCAST-TARGET
    function credit(int256 balance) external {
        uint256 asUnsigned = uint256(balance);
        balances[msg.sender] = asUnsigned;
    }
}
