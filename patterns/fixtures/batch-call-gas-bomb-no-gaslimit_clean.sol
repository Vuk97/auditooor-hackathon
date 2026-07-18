// SPDX-License-Identifier: MIT
// Fixture: batch-call-gas-bomb-no-gaslimit — CLEAN
// Detector MUST NOT fire on any function here.
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransfer(address to, uint256 amount) external;
}

contract BatchCallGasBombClean {
    IERC20Like public token;
    uint256 public constant MAX_CALL_GAS = 200_000;
    uint256 public constant BATCH_ENTRY_GAS = 150_000;

    // CLEAN fix #1: cap per-entry gas with `.call{gas: MAX_CALL_GAS}`.
    function executeBatch(address[] calldata targets, bytes[] calldata data) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call{gas: MAX_CALL_GAS}(data[i]);
            require(ok, "call failed");
        }
    }

    // CLEAN fix #2: named gasLimit member in the call option bag.
    function batchDelegate(address[] calldata impls, bytes[] calldata data) external {
        for (uint256 i = 0; i < impls.length; i++) {
            (bool ok, ) = impls[i].call{gas: BATCH_ENTRY_GAS}(data[i]);
            require(ok);
        }
    }

    // CLEAN fix #3: inline gas cap on `.call{value: ..., gas: ...}`.
    function payoutEth(address[] calldata recipients, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool ok, ) = recipients[i].call{value: amounts[i], gas: 30_000}("");
            require(ok, "send failed");
        }
    }

    // CLEAN fix #4: pull-payment pattern — no per-iteration external call.
    mapping(address => uint256) public pendingWithdrawals;

    function scheduleAirdrop(address[] calldata to, uint256[] calldata amt) external {
        for (uint256 i = 0; i < to.length; i++) {
            pendingWithdrawals[to[i]] += amt[i];
        }
    }

    function claim() external {
        uint256 owed = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        token.safeTransfer(msg.sender, owed);
    }
}
