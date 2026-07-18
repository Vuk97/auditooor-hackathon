// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SelfDestructClean {
    address public owner;

    // CLEAN: gated on msg.sender == owner
    function kill(address payable to) external {
        require(msg.sender == owner, "not owner");
        selfdestruct(to);
    }
}
