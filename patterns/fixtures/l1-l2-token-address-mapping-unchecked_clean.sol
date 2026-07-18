// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same shape as the vuln
/// fixture, but the function rejects L1==L2 address collisions and
/// additionally validates the pair via an enumerated `tokenMap[]` registry.
contract L1L2BridgeClean {
    mapping(address => uint256) public escrow;
    mapping(address => address) public tokenMap; // admin-curated L1 -> L2

    function deposit(
        address l1Token,
        address l2Token,
        uint256 amount
    ) external {
        // Direct collision guard.
        require(l1Token != l2Token, "l1/l2 collision");
        // Enumerated registry consult: only admin-allowlisted pairs accepted.
        require(tokenMap[l1Token] == l2Token, "unregistered pair");

        escrow[l1Token] += amount;
        // emit DepositInitiated(l1Token, l2Token, amount);
    }
}
