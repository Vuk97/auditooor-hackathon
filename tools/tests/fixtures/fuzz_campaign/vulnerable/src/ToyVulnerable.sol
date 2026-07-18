// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

// Toy contract used by tools/tests/test_fuzz_campaign.py to exercise
// the campaign wrapper end-to-end. The contract has a clear arithmetic
// drift on the withdraw path: withdrawing N reduces the recorded
// deposit by N-1 instead of N, so total recorded deposits monotonically
// drift upward relative to actual asset transfers. A reasonable
// invariant (sum-of-deposits == sum-of-withdrawals + currentBalance)
// is broken on a single withdraw call.
//
// The fixture path is tools/tests/fixtures/... NOT test_fixtures/, so
// foot-gun #2 (predicate-engine source-mapping leak) does not apply.
// We deliberately avoid the trigger-word convention chatter (no
// `// VULN`, `// BUG`, `// CLEAN`, `// FIXME`, `// missing`) so even if
// the foot-gun #2 scope were widened, this fixture stays clean.

contract ToyVulnerable {
    mapping(address => uint256) public deposits;
    uint256 public sumDeposits;
    uint256 public sumWithdraws;

    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
        sumDeposits += amount;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        // Off-by-one drift: subtract one less than actually withdrawn.
        // Across many withdraws, sumDeposits diverges from
        // sumWithdraws + outstanding-balance.
        if (amount > 0) {
            deposits[msg.sender] -= (amount - 1);
        }
        sumWithdraws += amount;
    }
}
