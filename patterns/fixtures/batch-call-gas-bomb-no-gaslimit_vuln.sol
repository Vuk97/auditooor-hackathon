// SPDX-License-Identifier: MIT
// Fixture: batch-call-gas-bomb-no-gaslimit — VULNERABLE
// Detector MUST fire on every function here.
pragma solidity ^0.8.20;

interface IERC20Like {
    function safeTransfer(address to, uint256 amount) external;
}

contract BatchCallGasBombVuln {
    IERC20Like public token;

    // VULN: governance-style multi-call. Attacker-supplied target with a
    // gas-burning fallback aborts the entire batch.
    function executeBatch(address[] calldata targets, bytes[] calldata data) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call(data[i]);
            require(ok, "call failed");
        }
    }

    // VULN: delegatecall batch — even more dangerous, attacker-controlled
    // storage writes + gas bomb.
    function batchDelegate(address[] calldata impls, bytes[] calldata data) external {
        for (uint256 i = 0; i < impls.length; i++) {
            (bool ok, ) = impls[i].delegatecall(data[i]);
            require(ok);
        }
    }

    // VULN: ETH distribution with `.transfer` per iteration — a contract
    // recipient with a reverting fallback gas-bombs the loop.
    function payoutEth(address[] calldata recipients, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(amounts[i]);
        }
    }

    // VULN: safeTransfer token airdrop — malicious ERC20 receiver on the
    // destination can burn gas in a post-transfer hook.
    function airdrop(address[] calldata to, uint256[] calldata amt) external {
        for (uint256 i = 0; i < to.length; i++) {
            token.safeTransfer(to[i], amt[i]);
        }
    }
}
