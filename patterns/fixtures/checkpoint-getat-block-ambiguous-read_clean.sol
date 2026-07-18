// SPDX-License-Identifier: MIT
// CLEAN: same accessor but with an explicit block-finality gate —
// `require(blockNumber < block.number)` — so the queried block is
// always in the past and its checkpoint list is frozen.
pragma solidity ^0.8.20;

contract ERC20VotesClean {
    struct Checkpoint { uint32 fromBlock; uint224 votes; }

    mapping(address => Checkpoint[]) internal _checkpoints;
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegates;

    error BLOCK_FINALIZED();

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

    // ── CLEAN: queried block must be STRICTLY older than current block ──
    // Any in-progress writes in the current block cannot affect a read
    // whose cutoff is already sealed (block.number - 1 or earlier).
    function getPastVotes(address account, uint256 blockNumber)
        external view returns (uint256)
    {
        require(block.number > blockNumber, "BLOCK_FINALIZED");
        return _upperBinaryLookup(_checkpoints[account], uint32(blockNumber));
    }

    function getVotesAt(address account, uint256 blockNumber)
        external view returns (uint256)
    {
        _validateBlock(blockNumber);
        return _upperBinaryLookup(_checkpoints[account], uint32(blockNumber));
    }

    function _validateBlock(uint256 blockNumber) internal view {
        if (blockNumber >= block.number) revert BLOCK_FINALIZED();
    }

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
