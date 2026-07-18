// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderErc4626FunctionsRevertBreakingSpecificationRVuln {
    function revert(address) internal {}
    function maxDeposit() external {
        revert(msg.sender);
    }
}
