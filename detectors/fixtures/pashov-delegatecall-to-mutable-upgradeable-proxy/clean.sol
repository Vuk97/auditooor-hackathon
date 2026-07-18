pragma solidity ^0.8.20;

interface IRewardsClaimModule {
    function claimRewards(bytes calldata data) external returns (uint256 claimed);
}

contract FixedRewardsWrapper {
    address public owner;
    address public immutable rewardsProxy;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address fixedRewardsProxy) {
        owner = msg.sender;
        rewardsProxy = fixedRewardsProxy;
    }

    function claimRewards(bytes calldata data) external returns (uint256 claimed) {
        (bool ok, bytes memory returndata) =
            rewardsProxy.call(abi.encodeCall(IRewardsClaimModule.claimRewards, data));
        require(ok, "call failed");
        return abi.decode(returndata, (uint256));
    }

    function rescue(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }
}
