// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICreditDelegation { function recalcCapacity() external; }

contract VaultRouterClean {
    uint256 public assetsUnderManagement;
    ICreditDelegation public credit;
    function deposit(uint256 a) external {
        assetsUnderManagement += a;
        _updateCreditCapacity();
    }
    function _updateCreditCapacity() internal { credit.recalcCapacity(); }
}
