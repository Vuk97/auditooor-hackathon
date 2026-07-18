// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean variant: each per-entry call is wrapped in try/catch and
// failures are skipped with a continue. The detector's negated-regex
// matches `try ` / `catch {` / `continue;` inside the body and the
// pattern does not fire.
interface IStrategy {
    function unwind(uint256 amount) external;
}

contract WithdrawalQueueSingleStrategyDosClean {
    struct Request {
        address user;
        uint256 amount;
        IStrategy strategy;
    }

    Request[] public withdrawQueue;
    IStrategy[] public strategies;

    event WithdrawalSkipped(address indexed user, uint256 index);

    function enqueue(uint256 amount, IStrategy strat) external {
        withdrawQueue.push(Request(msg.sender, amount, strat));
    }

    // CLEAN: try/catch around the per-entry call, skip on failure.
    function processWithdrawals() external {
        for (uint256 i = 0; i < withdrawQueue.length; i++) {
            Request memory r = withdrawQueue[i];
            try r.strategy.unwind(r.amount) {
                // ok
            } catch {
                emit WithdrawalSkipped(r.user, i);
                continue;
            }
        }
        delete withdrawQueue;
    }

    // CLEAN variant: low-level call with success-flag skip.
    function executeWithdrawals() external {
        for (uint256 i = 0; i < strategies.length; i++) {
            (bool success, ) = address(strategies[i]).call(
                abi.encodeWithSelector(IStrategy.unwind.selector, 1)
            );
            if (!success) {
                continue;
            }
        }
    }
}
