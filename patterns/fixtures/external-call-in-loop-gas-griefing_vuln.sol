// SPDX-License-Identifier: MIT
// Fixture: external-call-in-loop-gas-griefing — VULNERABLE
// Detector MUST fire on every function here.
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
}

contract ExternalCallInLoopGasGriefingVuln {
    address[] public recipients;
    uint256[] public amounts;
    IERC20Like public token;

    // VULN: iterates recipients and forwards ALL remaining gas via .call.
    // A malicious recipient can consume gas indefinitely and DoS the batch.
    function distributeEth(address[] calldata targets, uint256[] calldata amts) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call{value: amts[i]}("");
            require(ok, "send failed");
        }
    }

    // VULN: ETH `.transfer` per iteration with no try/catch. A contract
    // recipient whose fallback reverts stalls the loop.
    function payoutAll() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(amounts[i]);
        }
    }

    // VULN: SafeTransfer per iteration, no try/catch, no gas cap.
    function airdropTokens(address[] calldata to, uint256[] calldata amt) external {
        for (uint256 i = 0; i < to.length; i++) {
            token.safeTransfer(to[i], amt[i]);
        }
    }

    // VULN: `.call{value: ...}` without a `gas:` option — all gas forwarded.
    function batchRefund(address[] calldata users, uint256[] calldata refund) external {
        for (uint256 i = 0; i < users.length; i++) {
            (bool ok, ) = users[i].call{value: refund[i]}("");
            require(ok);
        }
    }
}
