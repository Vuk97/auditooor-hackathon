// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: forwards a caller-supplied target address to delegatecall with NO
// allow-list, constant check, or modifier. Classic SWC-112. An attacker
// passes a contract whose code rewrites slot 0 (owner) or selfdestructs
// this proxy.
contract DelegatecallUnchecked {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function forward(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
