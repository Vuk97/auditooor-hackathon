// SPDX-License-Identifier: MIT
// Fixture: lido-submit-reentrancy — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface ILido {
    function submit(address referral) external payable returns (uint256);
}

// Minimal nonReentrant implementation
abstract contract ReentrancyGuard {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract LidoSubmitReentrancyClean is ReentrancyGuard {
    ILido public lido;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    // CLEAN fix: nonReentrant modifier applied to the payable function that
    // forwards value into Lido.submit. Cross-function reentrancy is blocked.
    function deposit() external payable nonReentrant {
        uint256 minted = lido.submit{value: msg.value}(address(0));
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}
