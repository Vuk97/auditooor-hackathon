// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStETH {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

// VULN: stETH balance cached at deposit time — positive rebase creates over-withdrawal
// Loss ref: Lido stETH integration guides; Angle Protocol stETH collateral, 2023
// https://docs.lido.fi/guides/lido-tokens-integration-guide
contract StETHVaultVuln {
    IStETH public stETH;
    mapping(address => uint256) public deposited; // cached at deposit time

    constructor(address _steth) { stETH = IStETH(_steth); }

    // VULN: stores raw amount — stETH rebases change actual held balance
    function deposit(uint256 amount) external {
        stETH.transferFrom(msg.sender, address(this), amount);
        deposited[msg.sender] += amount; // cached — does not track rebase
    }

    // VULN: withdraws cached amount which may be less than actual owed (if slashed)
    // or enables others to over-withdraw by exploiting rebase timing
    function withdraw() external {
        uint256 amount = deposited[msg.sender];
        deposited[msg.sender] = 0;
        stETH.transfer(msg.sender, amount); // ignores post-rebase actual balance
    }
}
