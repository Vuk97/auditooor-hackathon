// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: selector/module/action/wrapper bindings are open to any caller.
contract SelectorRegistrationBypassBroadVulnerable {
    address public owner;
    mapping(bytes4 => address) public selectorTarget;
    mapping(bytes4 => address) public selectorModule;
    mapping(bytes4 => address) public selectorAction;
    mapping(bytes4 => address) public selectorWrapper;

    function setSelectorTarget(bytes4 selector, address target) external {
        selectorTarget[selector] = target;
    }

    function enableModule(bytes4 selector, address module) external {
        selectorModule[selector] = module;
    }

    function bindAction(bytes4 selector, address action) external {
        selectorAction[selector] = action;
    }

    function setWrapper(bytes4 selector, address wrapper) external {
        selectorWrapper[selector] = wrapper;
    }
}
