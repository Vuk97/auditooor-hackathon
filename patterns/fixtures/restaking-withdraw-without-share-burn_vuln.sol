// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — detector MUST fire.
/// A PufferVault-style restaking delegator moves underlying ETH out via an
/// EigenPod-shaped `validatorBalance -= amt` decrement and a direct transfer
/// to the withdrawer, but fails to burn the caller's delegated shares.
/// The un-burned shares continue to accrue rewards and distort slashing
/// distribution across remaining depositors.
contract RestakingWithdrawVuln {
    mapping(address => uint256) public delegatedShares;
    uint256 public validatorBalance;
    uint256 public totalDelegatedShares;

    function deposit() external payable {
        uint256 sharesOut = msg.value;
        delegatedShares[msg.sender] += sharesOut;
        totalDelegatedShares += sharesOut;
        validatorBalance += msg.value;
    }

    // VULN: removes assets from the pool but does NOT burn shares.
    function completeWithdrawal(uint256 amt) external {
        require(delegatedShares[msg.sender] >= amt, "insufficient");
        validatorBalance -= amt;
        payable(msg.sender).transfer(amt);
        // BUG: delegatedShares[msg.sender] is never decremented; totalDelegatedShares
        // is never decremented; next accrual mis-distributes across stale shares.
    }

    // VULN: same shape via an _removeAsset-style helper, no share burn.
    function processWithdraw(uint256 amt) external {
        _removeAsset(msg.sender, amt);
    }

    function _removeAsset(address to, uint256 amt) internal {
        validatorBalance -= amt;
        (bool ok, ) = payable(to).call{value: amt}("");
        require(ok);
        // BUG: no share accounting update.
    }
}
