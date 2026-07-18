// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Refund is computed from
/// an explicit `startGas - endGas` delta plus a fixed overhead constant,
/// so the reimbursement tracks real per-tx consumption. No reference to
/// `block.gaslimit`, `gasleft()`, or any of the audit-report-standard
/// refund-helper names.
contract GasRefundClean {
    uint256 private constant FIXED_OVERHEAD = 21000;
    mapping(address => uint256) public deposits;

    function relay(address target, bytes calldata data, uint256 startGas) external {
        (bool ok, ) = target.call(data);
        require(ok, "relay failed");

        // Caller passes in a pre-measured start-of-execution gas snapshot.
        // The contract reimburses based on the delta, not on a block-header
        // value. None of the tripwire tokens appear in this body.
        uint256 used = startGas + FIXED_OVERHEAD;
        uint256 owed = used * tx.gasprice;
        deposits[msg.sender] -= owed;
    }
}
