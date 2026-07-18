// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStEthLikePositive {
    function safeTransfer(address to, uint256 amount) external;
}

contract RebasingLstWithdrawQueuePositive {
    struct WithdrawRequest {
        uint256 amountToRedeem;
        bool claimed;
    }

    IStEthLikePositive public immutable stETH;
    mapping(address => WithdrawRequest) public withdrawRequest;

    constructor(IStEthLikePositive stETH_) {
        stETH = stETH_;
    }

    function queueWithdraw(uint256 amountToRedeem) external {
        withdrawRequest[msg.sender] = WithdrawRequest({
            amountToRedeem: amountToRedeem,
            claimed: false
        });
    }

    function claim() external {
        WithdrawRequest storage request = withdrawRequest[msg.sender];
        require(!request.claimed, "already claimed");
        request.claimed = true;
        stETH.safeTransfer(msg.sender, request.amountToRedeem);
    }
}
