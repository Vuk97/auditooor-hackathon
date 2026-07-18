// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// CLEAN: credits actual received amount via balance diff
contract StakingClean {
    IERC20 public token;
    mapping(address => uint256) public deposited;

    constructor(address _token) { token = IERC20(_token); }

    // CLEAN: balance diff pattern — FoT tokens credited correctly
    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        deposited[msg.sender] += received; // credits actual received, not parameter
    }

    function withdraw(uint256 amount) external {
        require(deposited[msg.sender] >= amount, "insufficient");
        deposited[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
