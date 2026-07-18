// SPDX-License-Identifier: MIT
// Fixture: subtraction-without-gt-check — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

// CLEAN: every balance/shares/total-mutating entrypoint has an explicit
// `require(x >= amount)`, `require(shares … )`, or
// `if (x < amount) revert …` pre-check. One path uses `unchecked`, which
// is an explicit opt-in to wrap semantics and also disqualifies the match.
contract SubWithoutGteClean {
    mapping(address => uint256) public balance;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;
    uint256 public totalShares;

    error InsufficientBalance(uint256 have, uint256 want);

    // CLEAN: `require(balance …)` form — matches the negative-guard regex.
    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "INSUFFICIENT_BALANCE");
        balance[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // CLEAN: `require(balance …)` on the plural-mapping form.
    function burn(uint256 amount) external {
        require(balances[msg.sender] >= amount, "INSUFFICIENT");
        balances[msg.sender] -= amount;
    }

    // CLEAN: `require(shares …)` form.
    function unstake(uint256 amount) external {
        require(shares[msg.sender] >= amount, "INSUFFICIENT_SHARES");
        shares[msg.sender] -= amount;
    }

    // CLEAN: `if (balance < amount) revert …` custom-error branch.
    function customErrorWithdraw(uint256 amount) external {
        if (balance[msg.sender] < amount) revert InsufficientBalance(balance[msg.sender], amount);
        balance[msg.sender] -= amount;
    }

    // CLEAN: author opted into wrap semantics explicitly with `unchecked`,
    // which is in the negative-guard regex. Detector must not fire.
    function intentionalWrap(uint256 amount) external {
        unchecked {
            totalSupply -= amount;
        }
    }

    // CLEAN: total* aggregate guarded with require on balance.
    function debitTotalGuarded(uint256 amount) external {
        require(balance[msg.sender] >= amount, "INSUFFICIENT_TOTAL");
        totalShares -= amount;
    }
}
