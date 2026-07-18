// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SelectorTargetBindingClean {
    address public owner;
    mapping(bytes4 => address) public selectorTarget;
    mapping(bytes4 => address) public selectorModule;
    mapping(bytes4 => address) public selectorAction;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setSelectorTarget(bytes4 selector, address target) external onlyOwner {
        selectorTarget[selector] = target;
    }

    function bindModule(bytes4 selector, address module) external onlyOwner {
        selectorModule[selector] = module;
    }

    function updateAction(bytes4 selector, address action) external onlyOwner {
        selectorAction[selector] = action;
    }
}
