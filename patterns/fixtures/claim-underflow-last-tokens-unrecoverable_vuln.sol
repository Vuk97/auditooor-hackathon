// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal token-claim contract. Raw subtraction in the claim path causes a
// panic-underflow whenever rounding or an admin recomputation makes
// `alreadyClaimed` exceed the current `total`, permanently stranding the
// user's last tokens.
contract ClaimUnderflowVuln {
    mapping(address => uint256) public alreadyClaimed;
    mapping(address => uint256) public totalAllocated;
    uint256 public globalScale = 1e18;

    function allocate(address user, uint256 amount) external {
        totalAllocated[user] = amount;
    }

    // VULN: raw subtraction. If globalScale is reduced or the pro-rata
    // computation rounds `total` below `alreadyClaimed[user]`, this panics.
    function claim() external returns (uint256) {
        uint256 total = (totalAllocated[msg.sender] * globalScale) / 1e18;
        uint256 claimable = total - alreadyClaimed[msg.sender];   // raw
        alreadyClaimed[msg.sender] = total;
        return claimable;
    }

    // VULN variant: claimRewards — same raw subtraction against an accumulator.
    function claimRewards(address user) external view returns (uint256) {
        uint256 vestedAmount = totalAllocated[user] * 2;
        return vestedAmount - alreadyClaimed[user];               // raw
    }

    // Admin hook that reduces the scale; this is what drives `total` below
    // `alreadyClaimed` and triggers the underflow on the next claim().
    function setScale(uint256 s) external {
        globalScale = s;
    }
}
