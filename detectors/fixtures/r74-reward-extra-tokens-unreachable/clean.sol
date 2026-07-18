pragma solidity ^0.8.20;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RewardExtraTokensUnreachableClean {
    IERC20Like[] public rewardTokens;
    IERC20Like public immutable airdropToken;
    address public immutable distributor;

    constructor(
        IERC20Like[] memory registeredRewards,
        IERC20Like unexpectedReward,
        address rewardDistributor
    ) {
        for (uint256 i = 0; i < registeredRewards.length; ++i) {
            rewardTokens.push(registeredRewards[i]);
        }
        airdropToken = unexpectedReward;
        distributor = rewardDistributor;
    }

    function harvest() external {
        for (uint256 i = 0; i < rewardTokens.length; ++i) {
            IERC20Like rewardToken = rewardTokens[i];
            uint256 amount = rewardToken.balanceOf(address(this));
            if (amount == 0) {
                continue;
            }
            rewardToken.transfer(distributor, amount);
        }

        forwardExtra(airdropToken, distributor);
    }

    function forwardExtra(IERC20Like extraReward, address recipient) internal {
        uint256 amount = extraReward.balanceOf(address(this));
        if (amount == 0) {
            return;
        }
        extraReward.transfer(recipient, amount);
    }
}
