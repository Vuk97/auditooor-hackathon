// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderMisuseOfTransientStorageForAuthenticationEipVuln {
    function tload(address) internal {}
    function targetFn() external {
        tload(msg.sender);
    }
}
