pragma solidity ^0.8.20;

contract StrategyWrapperPositive {
    struct Checkpoint {
        uint256 balance;
        mapping(address => uint256) rewardPerTokenPaid;
    }

    mapping(address => Checkpoint) internal checkpoints;
    mapping(address => uint256) internal extraRewardPerToken;
    address[] internal rewardTokens;
    uint256 internal totalSupply;

    function seedRewardToken(address token) external {
        rewardTokens.push(token);
    }

    function _deposit(uint256 amount) internal {
        Checkpoint storage checkpoint = checkpoints[msg.sender];

        for (uint256 i = 0; i < rewardTokens.length; ++i) {
            address token = rewardTokens[i];
            checkpoint.rewardPerTokenPaid[token] = extraRewardPerToken[token];
        }

        checkpoint.balance += amount;
        totalSupply += amount;
    }

    function deposit(uint256 amount) external {
        _deposit(amount);
    }
}
