// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SelfDestructVuln {
    // VULN: no access control on selfdestruct
    function kill(address payable to) external {
        selfdestruct(to);
    }
}
