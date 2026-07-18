// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but `finalizeWithdrawal` enforces BOTH the canonical-sender
/// bind and the per-message replay guard before any value-bearing state
/// change.
contract CrossChainReplayClean {
    address public messenger;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    mapping(bytes32 => bool) public processed;

    constructor(address _messenger) {
        messenger = _messenger;
    }

    function finalizeWithdrawal(
        bytes32 msgId,
        address to,
        uint256 amount
    ) external {
        require(msg.sender == messenger, "not canonical");
        require(!processed[msgId], "replay");
        processed[msgId] = true;

        balances[to] += amount;
        totalSupply += amount;
    }
}
