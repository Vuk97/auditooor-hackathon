// SPDX-License-Identifier: MIT
// Mirrors t3rn (Jun 2025) escrow refund shape: `isClaimable` checks
// `claimed` flag only; refund transfers stored `rewardAsset` without
// asserting it matches the order's deposit-time asset.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

contract EscrowRefundVuln {
    struct Order {
        address user;
        uint256 amount;
        address depositAsset;
    }

    mapping(uint256 => bool)   public claimed;
    mapping(uint256 => Order)  public orders;

    address public rewardAsset;

    function setRewardAsset(address a) external { rewardAsset = a; }

    function commit(uint256 id, uint256 amount) external {
        orders[id] = Order({
            user: msg.sender,
            amount: amount,
            depositAsset: rewardAsset
        });
    }

    function refund(uint256 id) external {
        Order memory o = orders[id];
        require(o.user == msg.sender, "not owner");
        require(!claimed[id], "claimed");
        claimed[id] = true;
        // No assertion that o.depositAsset == rewardAsset. If admin has
        // since flipped rewardAsset, user redeems the new asset.
        IERC20(rewardAsset).transfer(msg.sender, o.amount);
    }

    function claim(uint256 id) external {
        Order memory o = orders[id];
        require(o.user == msg.sender, "not owner");
        require(!claimed[id], "claimed");
        claimed[id] = true;
        IERC20(rewardAsset).transfer(msg.sender, o.amount);
    }
}
