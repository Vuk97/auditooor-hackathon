// SPDX-License-Identifier: MIT
// Fixture: external-call-in-loop-gas-griefing — CLEAN
// Detector MUST NOT fire on any function here.
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function safeTransfer(address to, uint256 amount) external;
}

contract ExternalCallInLoopGasGriefingClean {
    address[] public recipients;
    uint256[] public amounts;
    IERC20Like public token;
    uint256 public constant MAX_CALL_GAS = 30_000;

    mapping(address => uint256) public claimable;

    // CLEAN: bounded per-iteration gas via `.call{gas: MAX_CALL_GAS}`.
    // A griefer cannot consume more than MAX_CALL_GAS and the loop
    // continues.
    function distributeEth(address[] calldata targets, uint256[] calldata amts) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call{gas: MAX_CALL_GAS, value: amts[i]}("");
            // intentionally do not revert on single failure
            ok;
        }
    }

    // CLEAN: try/catch around the external call so a reverting recipient
    // doesn't poison the batch.
    function payoutAll() external {
        for (uint256 i = 0; i < recipients.length; i++) {
            try this._sendOne(recipients[i], amounts[i]) {
                // ok
            } catch {
                // skip failing recipient
            }
        }
    }

    function _sendOne(address to, uint256 amt) external {
        require(msg.sender == address(this));
        payable(to).transfer(amt);
    }

    // CLEAN: pull-payment pattern — no external call inside the loop at
    // all; recipients pull their share via `claim()`.
    function scheduleAirdrop(address[] calldata to, uint256[] calldata amt) external {
        for (uint256 i = 0; i < to.length; i++) {
            claimable[to[i]] += amt[i];
        }
    }

    function claim() external {
        uint256 amt = claimable[msg.sender];
        claimable[msg.sender] = 0;
        token.safeTransfer(msg.sender, amt);
    }

    // CLEAN: gasleft() precheck so the loop aborts cleanly before a
    // griefer-forwarded call can eat the remaining gas.
    function batchRefund(address[] calldata users, uint256[] calldata refund) external {
        for (uint256 i = 0; i < users.length; i++) {
            require(gasleft() > 50_000, "out of gas headroom");
            (bool ok, ) = users[i].call{gas: MAX_CALL_GAS, value: refund[i]}("");
            ok;
        }
    }
}
