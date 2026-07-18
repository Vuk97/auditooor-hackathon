// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: a registrar-controlled check is used instead of an authoritative owner/admin gate.
contract SelectorRegistrationBypassRegistrarVulnerable {
    address public owner;
    mapping(bytes4 => address) public selectorAction;
    mapping(bytes4 => address) public selectorModule;

    function registerAction(bytes4 selector, address action, address registrar) external {
        require(msg.sender == registrar, "not registrar");
        selectorAction[selector] = action;
    }

    function registerModule(bytes4 selector, address module, address registrar) external {
        require(msg.sender == registrar, "not registrar");
        selectorModule[selector] = module;
    }
}
