// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ExitPrecompileVuln {
    event Exit(address indexed recipient, uint256 amount);

    // VULN: exitToNear treats msg.value as the authoritative burn amount.
    // Under DELEGATECALL the caller's msg.value is preserved and the
    // precompile emits Exit events for ETH that never left the caller.
    function exitToNear(address recipient) external payable {
        uint256 amount = msg.value;
        emit Exit(recipient, amount);
    }
}
