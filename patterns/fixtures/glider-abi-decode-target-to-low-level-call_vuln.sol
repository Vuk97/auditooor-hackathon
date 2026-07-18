// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ArbitraryCallViaDecodeVuln {
    // Contract is expected to hold / receive approvals from users.
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULN: Seneca / Moonhacker / Arcadia pattern.
    // User-supplied `blob` is decoded into a target + calldata and executed.
    // Attacker supplies target = approvedToken, data = transferFrom(victim, attacker, X).
    function executeStrategy(bytes calldata blob) external returns (bytes memory) {
        (address target, bytes memory data) = abi.decode(blob, (address, bytes));
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "STRATEGY_FAIL");
        return ret;
    }
}
