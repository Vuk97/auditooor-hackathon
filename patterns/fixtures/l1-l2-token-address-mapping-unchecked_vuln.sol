// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// l1-l2-token-address-mapping-unchecked detector. DO NOT DEPLOY.
///
/// `deposit` pairs an L1 token address with an L2 token address taken
/// directly as user input. There is no `require(l1Token != l2Token)` and
/// no enumerated `tokenMap[]` consult; as a result an attacker who can
/// arrange matching addresses on both chains can break the pairing
/// invariant and drain escrow.
contract L1L2BridgeVuln {
    mapping(address => uint256) public escrow;

    function deposit(
        address l1Token,
        address l2Token,
        uint256 amount
    ) external {
        // No collision guard — l1Token and l2Token can be equal, chainId
        // is never consulted, no tokenMap[] registry lookup.
        escrow[l1Token] += amount;
        // emit DepositInitiated(l1Token, l2Token, amount);
    }
}
