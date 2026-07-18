// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

// CLEAN:
// - reward-token registration rejects the staking/PDT asset
// - admin withdrawal also rejects the staking/PDT asset
contract PDTStakingV2Clean {
    address public pdtToken;
    address[] public rewardTokenList;
    mapping(address => bool) public isRewardToken;
    address public tokenManager;

    modifier onlyRole(bytes32) {
        require(msg.sender == tokenManager, "not token manager");
        _;
    }

    bytes32 public constant TOKEN_MANAGER = keccak256("TOKEN_MANAGER");

    constructor(address _pdtToken, address _tokenManager) {
        pdtToken = _pdtToken;
        tokenManager = _tokenManager;
    }

    function registerNewRewardToken(address newRewardToken) external onlyRole(TOKEN_MANAGER) {
        require(newRewardToken != address(0), "invalid reward token");
        require(newRewardToken != pdtToken, "reward token cannot be PDT");
        require(!isRewardToken[newRewardToken], "exists");
        rewardTokenList.push(newRewardToken);
        isRewardToken[newRewardToken] = true;
    }

    function withdrawRewardToken(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(TOKEN_MANAGER) {
        require(token != pdtToken, "cannot withdraw PDT");
        IERC20Like(token).transfer(to, amount);
    }
}
