// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RG01NativeRewardStaleTotalAssetsCancelLockClean {
    mapping(address => uint256) public shares;
    mapping(uint256 => Lock) public locks;

    uint256 public totalShares;
    uint256 public totalDeposited;
    uint256 public accountedNativeRewards;
    uint256 public nativeBalanceLastKnown;
    uint256 public liveAssetBalance;
    uint256 public nextLockId;

    struct Lock {
        address user;
        uint256 amount;
        bool active;
    }

    function totalAssets() public view returns (uint256) {
        return liveAssetBalance;
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 mintedShares) {
        _accrueNativeRewards();
        mintedShares = _convertToShares(assets);
        _deposit(receiver, assets, mintedShares);
    }

    function redeem(uint256 shareAmount) external returns (uint256 lockId) {
        require(shares[msg.sender] >= shareAmount, "shares");

        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        totalDeposited -= shareAmount;
        liveAssetBalance -= shareAmount;
        nativeBalanceLastKnown -= shareAmount;

        lockId = nextLockId++;
        locks[lockId] = Lock({user: msg.sender, amount: shareAmount, active: true});
    }

    function fundNativeRewards(uint256 amount) external {
        liveAssetBalance += amount;
    }

    function cancelLock(uint256 lockId) external {
        Lock storage lock = locks[lockId];
        require(lock.user == msg.sender, "owner");
        require(lock.active, "inactive");

        uint256 amount = lock.amount;
        lock.active = false;
        _accrueNativeRewards();
        deposit(amount, msg.sender);
    }

    function poke() external {
        _accrueNativeRewards();
    }

    function _convertToShares(uint256 assets) internal view returns (uint256) {
        uint256 supply = totalShares;
        return supply == 0 ? assets : (assets * supply) / totalAssets();
    }

    function _deposit(address receiver, uint256 assets, uint256 mintedShares) internal {
        shares[receiver] += mintedShares;
        totalShares += mintedShares;
        totalDeposited += assets;
        liveAssetBalance += assets;
        nativeBalanceLastKnown += assets;
    }

    function _accrueNativeRewards() internal {
        uint256 accountedBalance = totalDeposited + accountedNativeRewards;
        if (liveAssetBalance > accountedBalance) {
            accountedNativeRewards += liveAssetBalance - accountedBalance;
            nativeBalanceLastKnown = liveAssetBalance;
        }
    }
}
