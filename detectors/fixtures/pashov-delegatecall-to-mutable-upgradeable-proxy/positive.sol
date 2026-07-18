pragma solidity ^0.8.20;

interface IRewardsProxy {
    function claimRewards(bytes calldata data) external returns (uint256 claimed);
}

interface IUpgradeableRewardsProxy {
    function upgradeToAndCall(address newImplementation, bytes calldata data) external;
}

contract MutableRewardsWrapper {
    address public owner;
    address private _rewardsProxy;

    event RewardsProxyUpdated(address indexed newRewardsProxy);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address initialRewardsProxy) {
        owner = msg.sender;
        _rewardsProxy = initialRewardsProxy;
    }

    function setRewardsProxy(address newRewardsProxy) external onlyOwner {
        _rewardsProxy = newRewardsProxy;
        emit RewardsProxyUpdated(newRewardsProxy);
    }

    function claimRewards(bytes calldata data) external returns (uint256 claimed) {
        (bool ok, bytes memory returndata) =
            _rewardsProxy.delegatecall(abi.encodeCall(IRewardsProxy.claimRewards, data));
        require(ok, "delegatecall failed");
        return abi.decode(returndata, (uint256));
    }

    function upgradeRewardsProxy(address newImplementation, bytes calldata initData) external onlyOwner {
        IUpgradeableRewardsProxy(_rewardsProxy).upgradeToAndCall(newImplementation, initData);
    }
}
