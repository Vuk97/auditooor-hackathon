// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: selector/module/action/wrapper bindings are owner-gated.
contract SelectorRegistrationBypassBroadSafe {
    address public owner;
    mapping(bytes4 => address) public selectorTarget;
    mapping(bytes4 => address) public selectorModule;
    mapping(bytes4 => address) public selectorAction;
    mapping(bytes4 => address) public selectorWrapper;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setSelectorTarget(bytes4 selector, address target) external onlyOwner {
        selectorTarget[selector] = target;
    }

    function enableModule(bytes4 selector, address module) external onlyOwner {
        selectorModule[selector] = module;
    }

    function bindAction(bytes4 selector, address action) external onlyOwner {
        selectorAction[selector] = action;
    }

    function setWrapper(bytes4 selector, address wrapper) external onlyOwner {
        selectorWrapper[selector] = wrapper;
    }
}
