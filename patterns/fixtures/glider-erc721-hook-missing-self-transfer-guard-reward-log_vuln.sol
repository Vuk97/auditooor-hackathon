// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderErc721HookMissingSelfTransferGuardRewardLogVuln {
    function _beforeTokenTransfer() external {
    }
}
