// Fixture: Curve-stablecoin-style pool with proper checks-effects-
// interactions ordering AND an OpenZeppelin ReentrancyGuard.
// Structurally similar to positive.sol but should NOT fire the
// w22_sol_reentrancy_curve_stable detector.
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

contract CurveStableLikePoolSafe is ReentrancyGuard {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // Negative: state mutated BEFORE external call AND nonReentrant guard.
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        // Effects first.
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        // Interactions last.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function getVirtualPrice() external view returns (uint256) {
        if (totalDeposits == 0) return 0;
        return (address(this).balance * 1e18) / totalDeposits;
    }
}
