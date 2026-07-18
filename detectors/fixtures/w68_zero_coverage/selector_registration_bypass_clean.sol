// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: selector registration is owner-gated.
contract SelectorRegistrationBypassSafe {
    address public owner;
    mapping(bytes4 => address) public selectorTarget;

    function registerSelector(bytes4 selector, address target) external {
        require(msg.sender == owner, "not owner");
        selectorTarget[selector] = target;
    }
}
