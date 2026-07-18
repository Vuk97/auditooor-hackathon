// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire.
///
/// transferFrom rotates ownership AND clears the stale per-token approval
/// via `delete tokenApprovals[tokenId]`. The body_not_contains_regex term
/// matches this clear, so the negative predicate evaluates false and the
/// detector does not fire.
contract NftApprovalOrphanedClean {
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

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(_owners[tokenId] == from, "wrong from");
        require(
            msg.sender == from || tokenApprovals[tokenId] == msg.sender,
            "not authorized"
        );
        balances[from] -= 1;
        balances[to] += 1;
        _owners[tokenId] = to;
        // Clear per-token approval so prior approval can't be reused by
        // the previous owner's operator against the new owner.
        delete tokenApprovals[tokenId];
    }
}
