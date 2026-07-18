// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RowAssetRefundClean {
    struct RefundOrder {
        address beneficiary;
        address rewardAsset;
        uint256 amount;
    }

    mapping(uint256 => bool) public claimed;
    mapping(uint256 => RefundOrder) public orders;

    address public expectedRewardAsset;

    function setExpectedRewardAsset(address asset) external {
        expectedRewardAsset = asset;
    }

    function createOrder(uint256 id, address rewardAsset, uint256 amount) external {
        require(rewardAsset == expectedRewardAsset, "wrong asset");
        orders[id] = RefundOrder({
            beneficiary: msg.sender,
            rewardAsset: rewardAsset,
            amount: amount
        });
    }

    function refund(uint256 id) external {
        RefundOrder memory order = orders[id];
        require(order.beneficiary == msg.sender, "not beneficiary");
        require(!claimed[id], "claimed");
        require(order.rewardAsset == expectedRewardAsset, "wrong asset");

        claimed[id] = true;
        IERC20(order.rewardAsset).transfer(msg.sender, order.amount);
    }
}
