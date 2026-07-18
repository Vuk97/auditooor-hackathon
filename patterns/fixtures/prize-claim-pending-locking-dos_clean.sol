// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPrizeReceiver {
    function onPrizeClaimed(uint256 amount) external;
}

// CLEAN: claimPrizes wraps the per-winner hook in try/catch, caps
// forwarded gas, and emits a ClaimFailed event on failure so the
// rest of the batch is paid even if one winner is griefing.
contract PrizePoolClean {
    mapping(address => uint256) public prize;
    mapping(address => bool) public claimable;
    address[] public winners;

    event PrizeClaimed(address indexed winner, uint256 amount);
    event ClaimFailed(address indexed winner, bytes reason);

    function register(address winner, uint256 amount) external {
        winners.push(winner);
        prize[winner] = amount;
        claimable[winner] = true;
    }

    // FIX: per-iteration try/catch with gas cap. A reverting hook only
    // skips its own winner; the rest of the batch is paid normally.
    function claimPrizes(address[] calldata winnersBatch) external {
        for (uint256 i = 0; i < winnersBatch.length; i++) {
            address w = winnersBatch[i];
            if (!claimable[w]) continue; // skip already-claimed
            uint256 amt = prize[w];
            claimable[w] = false;
            try IPrizeReceiver(w).onPrizeClaimed{gas: 100_000}(amt) {
                emit PrizeClaimed(w, amt);
            } catch (bytes memory reason) {
                // restore claimable so the winner can retry individually
                claimable[w] = true;
                emit ClaimFailed(w, reason);
            }
        }
    }
}
