// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: the delegatecall target is constrained to an explicit allow-list.
// Attackers cannot substitute an arbitrary implementation address.
contract DelegatecallAllowListed {
    address public owner;
    mapping(address => bool) public implementations;

    constructor(address initialImpl) {
        owner = msg.sender;
        implementations[initialImpl] = true;
    }

    function forward(address target, bytes calldata data) external returns (bytes memory) {
        require(implementations[target], "impl not allow-listed");
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
