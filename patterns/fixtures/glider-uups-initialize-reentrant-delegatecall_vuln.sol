// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract UUPSVuln {
    address public owner;
    bool private _init;

    function initialize(address hook, bytes calldata data) external {
        require(!_init, "inited");
        _init = true;
        owner = msg.sender;
        (bool ok,) = hook.delegatecall(data);
        require(ok, "hook");
    }
}
