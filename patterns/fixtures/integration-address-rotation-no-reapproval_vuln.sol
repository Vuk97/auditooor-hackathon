// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: admin setter rotates integration address without touching approvals.
// Modeled on Morpheus M-03 (Code4rena 2025-08): `setAavePool` swaps the
// pool pointer but does not revoke allowance on the old pool nor grant
// to the new one. Deposits brick; old pool retains dormant allowance.

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract VulnVault {
    address public owner;
    address public aavePool;
    address public router;
    address public strategy;
    IERC20 public immutable token;

    constructor(address _owner, address _token) {
        owner = _owner;
        token = IERC20(_token);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "!owner");
        _;
    }

    // VULN 1: rotates aavePool; never adjusts approvals.
    function setAavePool(address newPool) external onlyOwner {
        aavePool = newPool;
    }

    // VULN 2: rotates router with only event emission.
    function setRouter(address newRouter) external onlyOwner {
        router = newRouter;
    }

    // VULN 3: rotates strategy; uses direct assignment only.
    function switchStrategy(address newStrategy) external onlyOwner {
        strategy = newStrategy;
    }
}
