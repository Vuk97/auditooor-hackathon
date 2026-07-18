// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire. DO NOT DEPLOY.
///
/// `deposit` uses ERC-20 `transferFrom` on a caller-supplied token. If
/// `token` is ERC-777, the sender's registered `tokensToSend` hook runs
/// *inside* transferFrom and can re-enter this contract. State mutation
/// after the external call (shares[msg.sender] += amount) and the lack
/// of any nonReentrant modifier make the reentry exploitable.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Erc777ReceiverUncheckedReentrancyVuln {
    mapping(address => mapping(address => uint256)) public shares;

    function deposit(address token, uint256 amount) external {
        // External call to attacker-chosen token. ERC-777 tokensToSend
        // hook runs synchronously and calls back into this contract
        // before the state write below.
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // CEI violation: state mutation AFTER the external call with no
        // reentrancy guard.
        shares[token][msg.sender] += amount;
    }
}
