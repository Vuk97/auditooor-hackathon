// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPrizeReceiver {
    function onPrizeClaimed(uint256 amount) external;
}

// VULN: claimPrizes iterates winners and calls a user-supplied hook
// on each. A single reverting hook (malicious or buggy) reverts the
// entire batch. No try/catch, no skip-on-fail.
contract PrizePoolVuln {
    mapping(address => uint256) public prize;
    mapping(address => bool) public claimable;
    address[] public winners;

    function register(address winner, uint256 amount) external {
        winners.push(winner);
        prize[winner] = amount;
        claimable[winner] = true;
    }

    // BUG: per-winner notification is unguarded. One malicious winner
    // whose onPrizeClaimed() reverts (or consumes all gas) DoSes the
    // batch — no legitimate winner gets paid.
    function claimPrizes(address[] calldata winnersBatch) external {
        for (uint256 i = 0; i < winnersBatch.length; i++) {
            address w = winnersBatch[i];
            require(claimable[w], "already claimed");
            uint256 amt = prize[w];
            claimable[w] = false;
            IPrizeReceiver(w).onPrizeClaimed(amt);
        }
    }
}
