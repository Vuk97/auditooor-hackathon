// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract UUPSClean {
    address public owner;
    bool private _init;

    function initialize() external {
        require(!_init, "inited");
        _init = true;
        owner = msg.sender;
    }
}
