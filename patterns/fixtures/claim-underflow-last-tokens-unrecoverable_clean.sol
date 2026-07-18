// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: claim paths saturate the subtraction and short-circuit when
// the accumulator exceeds the current total, so rounding/admin changes can
// never DOS the claim function.
contract ClaimUnderflowClean {
    mapping(address => uint256) public alreadyClaimed;
    mapping(address => uint256) public totalAllocated;
    uint256 public globalScale = 1e18;

    function allocate(address user, uint256 amount) external {
        totalAllocated[user] = amount;
    }

    // CLEAN: explicit short-circuit `if (total >= claimed)` guard before the
    // subtraction — matches the saturate regex in the DSL and suppresses
    // detection.
    function claim() external returns (uint256) {
        uint256 total = (totalAllocated[msg.sender] * globalScale) / 1e18;
        if (total >= alreadyClaimed[msg.sender]) {
            uint256 claimable = total - alreadyClaimed[msg.sender];
            alreadyClaimed[msg.sender] = total;
            return claimable;
        }
        return 0;
    }

    // CLEAN variant: ternary saturating subtraction `? a - b : 0`.
    function claimRewards(address user) external view returns (uint256) {
        uint256 vestedAmount = totalAllocated[user] * 2;
        return vestedAmount >= alreadyClaimed[user]
            ? vestedAmount - alreadyClaimed[user]
            : 0;
    }

    function setScale(uint256 s) external {
        globalScale = s;
    }
}
