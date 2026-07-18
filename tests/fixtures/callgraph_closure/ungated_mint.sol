// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (e): privileged `_mint` reachable from an UNGATED public entrypoint,
// AND an admin-gated entrypoint that also reaches it (for contrast).
// unguarded_paths_to_sink(_mint) must enumerate BOTH `openMint` (guarded=False)
// and `adminMint` (guarded=True).
contract UngatedMint {
    address public owner;
    mapping(address => uint256) public balanceOf;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Sensitive sink.
    function _mint(address to, uint256 amt) internal {
        balanceOf[to] += amt;
    }

    // UNGATED public entrypoint reaching the sink — the bug.
    function openMint(uint256 amt) external {
        _mint(msg.sender, amt);
    }

    // Admin-gated entrypoint reaching the same sink — must be tagged guarded.
    function adminMint(address to, uint256 amt) external onlyOwner {
        _mint(to, amt);
    }

    // Public entrypoint that does NOT reach the sink — must not appear.
    function unrelated() external {
        owner = owner;
    }
}
