// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// VULN: credits `amount` parameter — fee-on-transfer tokens over-credited
// Loss ref: Safemoon/reflection token AMM exploits, BSC 2021-2022
// https://blog.openzeppelin.com/defi-security-pitfalls
contract StakingVuln {
    IERC20 public token;
    mapping(address => uint256) public deposited;

    constructor(address _token) { token = IERC20(_token); }

    // VULN: uses amount parameter — FoT tokens receive less, credit is wrong
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposited[msg.sender] += amount; // credits parameter, not actual received
        // With 5% FoT token: received = 0.95*amount, but credited = amount
        // User immediately withdraws amount = steal 0.05*amount from vault
    }

    function withdraw(uint256 amount) external {
        require(deposited[msg.sender] >= amount, "insufficient");
        deposited[msg.sender] -= amount;
        token.transfer(msg.sender, amount); // drains from others' deposits
    }
}
