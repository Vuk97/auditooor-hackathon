// SPDX-License-Identifier: MIT
// Fixture: lido-submit-reentrancy — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

interface ILido {
    function submit(address referral) external payable returns (uint256);
}

contract LidoSubmitReentrancyVuln {
    ILido public lido;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // VULN: payable function forwards ETH into Lido.submit() and then mutates
    // the shares mapping WITHOUT a nonReentrant guard. Any re-entry path that
    // reaches back into `deposit` observes the pre-update `shares[msg.sender]`.
    function deposit() external payable {
        uint256 minted = lido.submit{value: msg.value}(address(0));
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}
