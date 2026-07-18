// SPDX-License-Identifier: MIT
// Clean variant of t3rn escrow shape: refund path asserts the stored
// deposit-time asset still matches the contract's current rewardAsset
// before transferring. Detector must NOT fire.
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

contract EscrowRefundClean {
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
        require(o.depositAsset == rewardAsset, "asset mismatch");
        claimed[id] = true;
        IERC20(rewardAsset).transfer(msg.sender, o.amount);
    }

    function claim(uint256 id) external {
        Order memory o = orders[id];
        require(o.user == msg.sender, "not owner");
        require(!claimed[id], "claimed");
        require(o.depositAsset == rewardAsset, "asset mismatch");
        claimed[id] = true;
        IERC20(rewardAsset).transfer(msg.sender, o.amount);
    }
}
