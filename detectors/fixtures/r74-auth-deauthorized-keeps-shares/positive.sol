// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PermissionedYieldSharesPositive {
    mapping(address => bool) public authorized;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;
    uint256 public rewardIndex;

    event Authorized(address indexed account);
    event Deauthorized(address indexed account);

    function authorize(address account) external {
        authorized[account] = true;
        emit Authorized(account);
    }

    function deposit(uint256 assets) external {
        require(authorized[msg.sender], "not authorized");
        shares[msg.sender] += assets;
        totalSupply += assets;
    }

    function accrue(uint256 reward) external {
        require(totalSupply != 0, "empty");
        rewardIndex += reward * 1e18 / totalSupply;
    }

    function claimable(address account) external view returns (uint256) {
        return shares[account] * rewardIndex / 1e18;
    }

    function removeFromWhitelist(address account) external {
        authorized[account] = false;
        emit Deauthorized(account);
    }
}
