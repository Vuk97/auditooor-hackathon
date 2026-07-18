// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal batch withdrawal processor. The queue is iterated without
// any try/catch or skip-on-fail; a single reverting entry reverts
// the entire batch and DoS's every other pending withdrawal. This is
// the C0213 bug shape.
interface IStrategy {
    function unwind(uint256 amount) external;
}

contract WithdrawalQueueSingleStrategyDosVuln {
    struct Request {
        address user;
        uint256 amount;
        IStrategy strategy;
    }

    Request[] public withdrawQueue;
    IStrategy[] public strategies;

    function enqueue(uint256 amount, IStrategy strat) external {
        withdrawQueue.push(Request(msg.sender, amount, strat));
    }

    // VULN: iterates the queue; no try/catch, one reverting strategy
    // reverts the whole batch.
    function processWithdrawals() external {
        for (uint256 i = 0; i < withdrawQueue.length; i++) {
            Request memory r = withdrawQueue[i];
            r.strategy.unwind(r.amount);
        }
        delete withdrawQueue;
    }

    // VULN variant: same DoS shape, different entry point name.
    function executeWithdrawals() external {
        for (uint256 i = 0; i < strategies.length; i++) {
            strategies[i].unwind(1);
        }
    }
}
