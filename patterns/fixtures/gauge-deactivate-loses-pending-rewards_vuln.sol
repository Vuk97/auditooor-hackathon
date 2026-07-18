// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: killGauge deletes the gauge's reward-per-token bookkeeping
// without snapshotting each staker's accrued-but-unclaimed rewards
// first. After the kill, earned(user) derives zero and any pending
// claim is permanently lost.
contract GaugeControllerVuln {
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

    // BUG: deletes gauge state — including the rewardPerTokenStored
    // that claim() needs — without flushing any user's pending reward
    // into a claimable ledger first. Users with unclaimed accruals in
    // the current epoch lose them permanently.
    function killGauge(address g) external onlyOwner {
        delete gauges[g];
    }

    function claim(address g) external {
        Gauge storage gauge = gauges[g];
        uint256 owed = balances[g][msg.sender]
            * (gauge.rewardPerTokenStored - userRewardPerTokenPaid[g][msg.sender]);
        userRewardPerTokenPaid[g][msg.sender] = gauge.rewardPerTokenStored;
        // transfer owed to msg.sender (omitted for brevity)
        owed;
    }
}
