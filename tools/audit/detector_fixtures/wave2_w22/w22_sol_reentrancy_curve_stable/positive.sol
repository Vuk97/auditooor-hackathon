// Fixture: Curve-stablecoin-style read-only re-entrancy via external call
// before state update. Mirrors the audit-pin shape in the re-entrancy
// preview JSONL (Curve stablecoin x3). The pattern: a withdraw-style path
// transfers ETH/tokens to an arbitrary recipient BEFORE updating internal
// accounting, while the contract does NOT carry the standard
// ReentrancyGuard `nonReentrant` modifier on the entry function.
//
// Detector w22_sol_reentrancy_curve_stable should fire on this file.
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

interface IERC20Receiver {
    function onReceive(uint256 amount) external;
}

contract CurveStableLikePool {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // Positive: external call before state mutation, no nonReentrant guard.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // EXTERNAL CALL FIRST -- read-only re-entrancy and balance-drain
        // re-entrancy both reachable from here.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        // State updated AFTER external call.
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    function getVirtualPrice() external view returns (uint256) {
        if (totalDeposits == 0) return 0;
        return (address(this).balance * 1e18) / totalDeposits;
    }
}
