// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: settlement routes overflow to a treasury surplus buffer so
// lpPool <= lpPoolCap invariant holds.
contract CleanLottery {
    uint256 public lpPool;
    uint256 public lpPoolCap;
    uint256 public treasury;
    address public owner;

    constructor(address _owner, uint256 _cap) {
        owner = _owner;
        lpPoolCap = _cap;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "!owner");
        _;
    }

    function depositToLP(uint256 amount) external {
        require(lpPool + amount <= lpPoolCap, "cap");
        lpPool += amount;
    }

    function settleDraw(uint256 unclaimedJackpot, uint256 retainedRake) external {
        uint256 total = unclaimedJackpot + retainedRake;
        uint256 room = lpPoolCap - lpPool;
        if (total > room) {
            lpPool = lpPoolCap;
            treasury += total - room;
        } else {
            lpPool += total;
        }
    }

    function distributeProfits(uint256 profit) external {
        uint256 room = lpPoolCap - lpPool;
        if (profit > room) {
            lpPool = lpPoolCap;
            treasury += profit - room;
        } else {
            lpPool += profit;
        }
    }
}
