// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

// Fixture: vulnerable — withdrawBPT has no reentrancy guard; delete after transfer.
// Source: balancer/balancer-v3-monorepo@b100677 (LBP audit fix)

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract BPTTimeLocker {
    using SafeERC20 for IERC20;

    mapping(uint256 => uint256) internal _unlockTimestamps;
    mapping(address => mapping(uint256 => uint256)) internal _balances;

    error NoLockedBPT();
    error BPTStillLocked(uint256 unlockTimestamp);

    // VULNERABLE: no nonReentrant; delete happens after transfer
    function withdrawBPT(address bptAddress) public {
        uint256 id = uint256(uint160(bptAddress));
        uint256 amount = _balances[msg.sender][id];
        if (amount == 0) revert NoLockedBPT();

        uint256 unlockTimestamp = _unlockTimestamps[id];
        if (block.timestamp < unlockTimestamp) revert BPTStillLocked(unlockTimestamp);

        // BUG: _burn before delete but safeTransfer is external — can re-enter
        _balances[msg.sender][id] = 0;
        // External call BEFORE delete — reentrancy possible via ERC777/hooks
        IERC20(bptAddress).safeTransfer(msg.sender, amount);
        // delete happens AFTER the transfer
        delete _unlockTimestamps[id];
    }
}
