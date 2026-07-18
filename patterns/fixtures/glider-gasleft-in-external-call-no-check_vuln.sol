// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GasLeftVuln {
    // VULN: forwards gasleft() with no minimum check
    function forwardCall(address target, bytes calldata data) external returns (bool) {
        (bool ok, ) = target.call{gas: gasleft()}(data);
        return ok;
    }
}
