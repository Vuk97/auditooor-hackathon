// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Fixture: fixed — nonReentrant guard added, state cleared before transfer.
// Source: balancer/balancer-v3-monorepo@b100677 (LBP audit fix)

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract BPTTimeLocker is ReentrancyGuard {
    using SafeERC20 for IERC20;

    mapping(uint256 => uint256) internal _unlockTimestamps;
    mapping(address => mapping(uint256 => uint256)) internal _balances;

    error NoLockedBPT();
    error BPTStillLocked(uint256 unlockTimestamp);

    // FIXED: nonReentrant + burn before delete + delete before transfer (CEI)
    function withdrawBPT(address bptAddress) public nonReentrant {
        uint256 id = uint256(uint160(bptAddress));
        uint256 amount = _balances[msg.sender][id];
        if (amount == 0) revert NoLockedBPT();

        uint256 unlockTimestamp = _unlockTimestamps[id];
        if (block.timestamp < unlockTimestamp) revert BPTStillLocked(unlockTimestamp);

        // State updates before external call (CEI)
        _balances[msg.sender][id] = 0;
        delete _unlockTimestamps[id];

        IERC20(bptAddress).safeTransfer(msg.sender, amount);
    }
}
