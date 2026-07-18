// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

contract CasimirInstantUnstakeClean {
    uint256 private constant POOL_CAPACITY = 32 ether;

    mapping(address => uint256) private userStake;
    uint256 public requestedWithdrawalBalance;
    uint256 public requestedExits;
    uint256 public prepoolBalance;
    uint256 public exitedBalance;
    uint32[] public stakedPoolIds;

    function depositStake() external payable {
        userStake[msg.sender] += msg.value;
        prepoolBalance += msg.value;
    }

    function requestUnstake(uint256 amount) external {
        require(userStake[msg.sender] >= amount, "stake");
        userStake[msg.sender] -= amount;

        uint256 availableWithdrawalBalance = getWithdrawableBalance();
        if (amount <= availableWithdrawalBalance) {
            prepoolBalance -= amount;
            payable(msg.sender).transfer(amount);
            return;
        }

        requestedWithdrawalBalance += amount;
        uint256 coveredExitBalance = requestedExits * POOL_CAPACITY;
        uint256 exitDeficit = requestedWithdrawalBalance > coveredExitBalance + availableWithdrawalBalance
            ? requestedWithdrawalBalance - coveredExitBalance - availableWithdrawalBalance
            : 0;
        if (exitDeficit > 0) {
            uint256 exitsRequired = exitDeficit / POOL_CAPACITY;
            if (exitDeficit % POOL_CAPACITY > 0) {
                exitsRequired++;
            }
            requestExits(exitsRequired);
        }
    }

    function getWithdrawableBalance() public view returns (uint256) {
        return prepoolBalance + exitedBalance;
    }

    function requestExits(uint256 count) private {
        while (count > 0) {
            requestedExits++;
            count--;
        }
    }
}
