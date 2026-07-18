// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: any caller can register a function selector to an arbitrary
// implementation target - selector registry has no authority check.
contract SelectorRegistrationBypassVulnerable {
    address public owner;
    mapping(bytes4 => address) public selectorTarget;

    function registerSelector(bytes4 selector, address target) external {
        selectorTarget[selector] = target;
    }
}
