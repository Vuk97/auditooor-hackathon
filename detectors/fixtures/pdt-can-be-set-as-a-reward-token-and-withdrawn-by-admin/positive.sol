// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

// VULNERABLE:
// - registerNewRewardToken never rejects the staking/PDT asset
// - admin withdrawRewardToken can move arbitrary tokens and never rejects PDT
contract PDTStakingV2Positive {
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
        require(!isRewardToken[newRewardToken], "exists");
        rewardTokenList.push(newRewardToken);
        isRewardToken[newRewardToken] = true;
    }

    function withdrawRewardToken(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(TOKEN_MANAGER) {
        IERC20Like(token).transfer(to, amount);
    }
}
