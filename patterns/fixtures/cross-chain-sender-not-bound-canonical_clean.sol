// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but `finalizeDeposit` binds msg.sender to the canonical
/// messenger at the top of the function body, preventing direct EOA
/// invocation.
contract FinalizeDepositClean {
    address public messenger;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public processed;

    constructor(address _messenger) {
        messenger = _messenger;
    }

    function finalizeDeposit(
        bytes32 msgId,
        address to,
        uint256 amount
    ) external {
        require(msg.sender == messenger, "not messenger");
        require(!processed[msgId], "replay");
        processed[msgId] = true;
        balances[to] += amount;
    }
}
