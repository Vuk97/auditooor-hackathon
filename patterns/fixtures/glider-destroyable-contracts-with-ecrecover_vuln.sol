// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderDestroyableContractsWithEcrecoverVuln {
    function selfdestruct(address) internal {}
    function targetFn() external {
        selfdestruct(msg.sender);
    }
}
