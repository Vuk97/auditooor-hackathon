// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SelectorTargetBindingPositive {
    mapping(bytes4 => address) public selectorTarget;
    mapping(bytes4 => address) public selectorModule;
    mapping(bytes4 => address) public selectorAction;

    function setSelectorTarget(bytes4 selector, address target) external {
        selectorTarget[selector] = target;
    }

    function bindModule(bytes4 selector, address module) external {
        selectorModule[selector] = module;
    }

    function updateAction(bytes4 selector, address action) external {
        selectorAction[selector] = action;
    }
}
