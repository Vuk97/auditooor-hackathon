// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RouterAdapterArbitraryTargetCallVuln {
    mapping(address => uint256) public deposits;

    function swap(address target, bytes calldata data) external returns (bytes memory) {
        // VULN: no allowlist on `target`. Attacker can pass USDT and craft
        // `data = transferFrom(victim, attacker, amount)`.
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "call failed");
        return ret;
    }
}
