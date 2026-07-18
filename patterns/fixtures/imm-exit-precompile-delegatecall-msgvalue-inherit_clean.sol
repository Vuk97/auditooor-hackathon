// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExitPrecompileClean {
    event Exit(address indexed recipient, uint256 amount);
    address private immutable __self;

    constructor() { __self = address(this); }

    // FIXED: reject DELEGATECALL invocation via __self pinning.
    function exitToNear(address recipient) external payable {
        require(address(this) == __self, "delegated");
        uint256 amount = msg.value;
        emit Exit(recipient, amount);
    }
}
