// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire. DO NOT DEPLOY.
///
/// A minimal token-bridge receive side. The inbound message names the
/// token contract and the bridge blindly calls transferFrom on it. No
/// allowlist is consulted, so an attacker can register a malicious token
/// whose transferFrom either returns true without moving funds (to
/// inflate the recipient balance) or re-enters the bridge through an
/// ERC-777-style hook to corrupt escrow accounting.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract BridgeTokenAllowlistVuln {
    mapping(address => mapping(address => uint256)) public balanceOf; // token => user => credit

    // Precondition trigger: contract has a function whose body contains
    // one of the bridge markers. The allowlist check is intentionally
    // absent from the entry function below.
    function _handleBridge(address, address, uint256) internal pure {
        // placeholder so the precondition regex matches at contract scope
    }

    function receiveTokens(
        address token,
        address from,
        address to,
        uint256 amount
    ) external {
        // No allowlist / whitelist / supportedTokens check. Attacker
        // supplies any token they deploy.
        IERC20(token).transferFrom(from, address(this), amount);
        balanceOf[token][to] += amount;
    }
}
