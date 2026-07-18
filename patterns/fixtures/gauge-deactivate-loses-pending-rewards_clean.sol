// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: killGauge snapshots each user's pending reward into a
// per-user claimable ledger before deleting gauge state. Users can
// still claim what they earned prior to the kill.
contract GaugeControllerClean {
    address public owner;

    struct Gauge {
        uint256 totalSupply;
        uint256 rewardPerTokenStored;
        uint256 periodFinish;
        bool active;
    }

    mapping(address => Gauge) public gauges;
    mapping(address => mapping(address => uint256)) public userRewardPerTokenPaid;
    mapping(address => mapping(address => uint256)) public balances;
    mapping(address => mapping(address => uint256)) public pendingRewards;

    address[] internal _gaugeStakers;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addGauge(address g) external onlyOwner {
        gauges[g] = Gauge({
            totalSupply: 0,
            rewardPerTokenStored: 0,
            periodFinish: block.timestamp + 7 days,
            active: true
        });
    }

    // FIX: snapshot pending rewards for all stakers before deleting
    // the gauge. Uses the pendingRewards ledger that survives the kill
    // and can still be claimed afterwards.
    function killGauge(address g) external onlyOwner {
        _flushRewards(g);
        Gauge storage gauge = gauges[g];
        gauge.active = false;
        // state is marked inactive, but rewardPerTokenStored is retained
        // so snapshotRewards / claimPending remain derivable.
    }

    function _flushRewards(address g) internal {
        Gauge storage gauge = gauges[g];
        for (uint256 i = 0; i < _gaugeStakers.length; i++) {
            address user = _gaugeStakers[i];
            uint256 owed = balances[g][user]
                * (gauge.rewardPerTokenStored - userRewardPerTokenPaid[g][user]);
            pendingRewards[g][user] += owed;
            userRewardPerTokenPaid[g][user] = gauge.rewardPerTokenStored;
        }
    }

    function claimPending(address g) external {
        uint256 owed = pendingRewards[g][msg.sender];
        pendingRewards[g][msg.sender] = 0;
        // transfer owed to msg.sender (omitted for brevity)
        owed;
    }
}
