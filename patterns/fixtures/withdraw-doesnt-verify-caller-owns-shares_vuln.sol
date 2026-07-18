// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract WithdrawNoOwnershipCheckVuln {
    mapping(address => uint256) public shares;
    mapping(address => mapping(address => uint256)) public allowance;

    // VULN: accepts `owner` as a parameter, burns owner's shares, sends to
    // receiver. Never checks msg.sender == owner, never consumes allowance.
    // Any EOA can drain any depositor.
    function withdraw(uint256 amount, address receiver, address owner) external {
        shares[owner] -= amount;
        payable(receiver).transfer(amount);
    }

    // VULN: same issue, redeem flavor.
    function redeem(uint256 shareAmt, address owner) external {
        shares[owner] -= shareAmt;
        payable(msg.sender).transfer(shareAmt);
    }

    receive() external payable {}
}
