// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GliderBlockhashUsageThatCanLeadToAStalenessVuln {
    function blockhash(address) internal {}
    function targetFn() external {
        blockhash(msg.sender);
    }
}
