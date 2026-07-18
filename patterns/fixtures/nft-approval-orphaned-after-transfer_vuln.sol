// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// nft-approval-orphaned-after-transfer detector. DO NOT DEPLOY.
///
/// transferFrom rotates _owners[tokenId] but never clears the per-token
/// approval in tokenApprovals. Stale approval from the previous owner
/// survives the transfer and is usable by the approved operator to
/// transfer the token again.
contract NftApprovalOrphanedVuln {
    mapping(uint256 => address) internal _owners;
    mapping(uint256 => address) public tokenApprovals;
    mapping(address => uint256) public balances;

    function mint(address to, uint256 tokenId) external {
        _owners[tokenId] = to;
        balances[to] += 1;
    }

    function approve(address spender, uint256 tokenId) external {
        require(_owners[tokenId] == msg.sender, "not owner");
        tokenApprovals[tokenId] = spender;
    }

    // VULNERABLE: writes _owners (rotates ownership) but never clears
    // tokenApprovals[tokenId]. Stale approval survives the transfer.
    function transferFrom(address from, address to, uint256 tokenId) external {
        require(_owners[tokenId] == from, "wrong from");
        require(
            msg.sender == from || tokenApprovals[tokenId] == msg.sender,
            "not authorized"
        );
        balances[from] -= 1;
        balances[to] += 1;
        _owners[tokenId] = to;
        // VULN: ownership rotates without clearing the per-token approval.
    }
}
