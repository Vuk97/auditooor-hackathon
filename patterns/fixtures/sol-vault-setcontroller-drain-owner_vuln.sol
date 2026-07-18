// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultControllerVuln {
    address public owner = msg.sender;
    address public controller;
    function setController(address c) external {
        require(msg.sender == owner);
        controller = c;
    }
}
