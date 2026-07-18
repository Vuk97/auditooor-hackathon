// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: registrar-shaped registration is still owner-gated.
contract SelectorRegistrationBypassRegistrarSafe {
    address public owner;
    mapping(bytes4 => address) public selectorAction;
    mapping(bytes4 => address) public selectorModule;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function registerAction(bytes4 selector, address action, address registrar) external onlyOwner {
        require(registrar != address(0), "bad registrar");
        selectorAction[selector] = action;
    }

    function registerModule(bytes4 selector, address module, address registrar) external onlyOwner {
        require(registrar != address(0), "bad registrar");
        selectorModule[selector] = module;
    }
}
