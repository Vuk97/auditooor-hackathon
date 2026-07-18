// SPDX-License-Identifier: MIT
// VULN: ERC20Votes subclass exposing a getAt-style accessor that binary-
// searches the checkpoints array WITHOUT requiring the queried block to
// be strictly older than the current block. A flash-mint → self-delegate
// → vote → burn pattern within a single block produces a read value that
// is not yet final, enabling vote-weight manipulation on Governor._getVotes.
pragma solidity ^0.8.20;

contract ERC20VotesVuln {
    struct Checkpoint { uint32 fromBlock; uint224 votes; }

    mapping(address => Checkpoint[]) internal _checkpoints;
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegates;

    event DelegateVotesChanged(address indexed delegatee, uint256 previousBalance, uint256 newBalance);

    // Binary-search helper — OpenZeppelin-style findUpperBound
    function _upperBinaryLookup(Checkpoint[] storage ckpts, uint32 blockNumber)
        private view returns (uint224)
    {
        uint256 len = ckpts.length;
        if (len == 0) return 0;
        uint256 low = 0;
        uint256 high = len;
        while (low < high) {
            uint256 mid = (low + high) / 2;
            if (ckpts[mid].fromBlock > blockNumber) high = mid;
            else low = mid + 1;
        }
        return low == 0 ? 0 : ckpts[low - 1].votes;
    }

    // ── VULN: no `require(blockNumber < block.number)` guard ───────────
    // Governor calls `getPastVotes(user, block.number)` during proposal
    // execution — but the checkpoints array for THIS block is still
    // mutable. An attacker can push more entries later in the same tx
    // batch, or more subtly: flash-mint tokens → self-delegate → have
    // Governor read the inflated value → burn tokens — all atomically.
    function getPastVotes(address account, uint256 blockNumber)
        external view returns (uint256)
    {
        return _upperBinaryLookup(_checkpoints[account], uint32(blockNumber));
    }

    function getVotesAt(address account, uint256 blockNumber)
        external view returns (uint256)
    {
        return _upperBinaryLookup(_checkpoints[account], uint32(blockNumber));
    }

    // Write paths (abbreviated — the canonical same-block-multiple-entries
    // bug is orthogonal to this one; this fixture is about the READ side).
    function _writeCheckpoint(address delegatee, uint224 newVotes) internal {
        _checkpoints[delegatee].push(Checkpoint({
            fromBlock: uint32(block.number),
            votes: newVotes
        }));
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        address d = delegates[to];
        if (d != address(0)) _writeCheckpoint(d, uint224(balanceOf[to]));
    }

    function delegate(address to) external {
        delegates[msg.sender] = to;
        _writeCheckpoint(to, uint224(balanceOf[msg.sender]));
    }
}
