// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: lottery LP pool cap is checked on deposit but not in settlement
// paths — settleDraw credits the pool directly, pushing it over cap.
// Modeled on Megapot H-03 (Code4rena 2025-11).
contract VulnLottery {
    uint256 public lpPool;
    uint256 public lpPoolCap;
    address public owner;

    constructor(address _owner, uint256 _cap) {
        owner = _owner;
        lpPoolCap = _cap;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "!owner");
        _;
    }

    // Deposit side — enforces cap.
    function depositToLP(uint256 amount) external {
        require(lpPool + amount <= lpPoolCap, "cap");
        lpPool += amount;
    }

    // VULN 1: settleDraw credits unclaimed jackpot without checking cap.
    function settleDraw(uint256 unclaimedJackpot, uint256 retainedRake) external {
        // bug: no cap check; lpPool may exceed lpPoolCap.
        lpPool += unclaimedJackpot + retainedRake;
    }

    // VULN 2: distribute rewards without cap check.
    function distributeProfits(uint256 profit) external {
        lpPool = lpPool + profit;
    }

    // VULN 3: settlement accrual in a helper.
    function _recordWinnings(uint256 winAmt) internal {
        lpPool += winAmt;
    }

    function bookWinnings(uint256 winAmt) external {
        _recordWinnings(winAmt);
    }

    // Governance tries to shrink cap but cannot while lpPool > new cap.
    function setLPPoolCap(uint256 newCap) external onlyOwner {
        require(newCap >= lpPool, "shrink-fail"); // un-reachable if above
        lpPoolCap = newCap;
    }
}
