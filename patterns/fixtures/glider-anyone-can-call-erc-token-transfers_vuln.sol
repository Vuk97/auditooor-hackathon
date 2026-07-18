// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderAnyoneCanCallErcTokenTransfersVuln {
    function transfer(address) internal {}
    function targetFn() external {
        transfer(msg.sender);
    }
}
