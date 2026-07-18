// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStEthLikeClean {
    function safeTransfer(address to, uint256 amount) external;
    function getPooledEthByShares(uint256 sharesAmount) external view returns (uint256);
    function getSharesByPooledEth(uint256 pooledEthAmount) external view returns (uint256);
}

contract RebasingLstWithdrawQueueClean {
    struct WithdrawRequest {
        uint256 sharesOwed;
        bool claimed;
    }

    IStEthLikeClean public immutable stETH;
    mapping(address => WithdrawRequest) public withdrawRequest;

    constructor(IStEthLikeClean stETH_) {
        stETH = stETH_;
    }

    function queueWithdraw(uint256 assets) external {
        uint256 shares = stETH.getSharesByPooledEth(assets);
        withdrawRequest[msg.sender] = WithdrawRequest({
            sharesOwed: shares,
            claimed: false
        });
    }

    function claim() external {
        WithdrawRequest storage request = withdrawRequest[msg.sender];
        require(!request.claimed, "already claimed");
        request.claimed = true;
        uint256 payout = stETH.getPooledEthByShares(request.sharesOwed);
        stETH.safeTransfer(msg.sender, payout);
    }
}
