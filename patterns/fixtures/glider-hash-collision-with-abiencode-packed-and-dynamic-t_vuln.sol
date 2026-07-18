// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderHashCollisionWithAbiencodePackedAndDynamicTVuln {
    function abi(address) internal {}
    function targetFn() external {
        abi(msg.sender);
    }
}
