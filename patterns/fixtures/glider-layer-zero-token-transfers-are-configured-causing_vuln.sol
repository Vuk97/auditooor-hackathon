// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderLayerZeroTokenTransfersAreConfiguredCausingVuln {
    function send(address) internal {}
    function targetFn() external {
        send(msg.sender);
    }
}
