// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for the
/// lido-deposit-blocked-by-attacker detector. DO NOT DEPLOY.
///
/// `deposit()` reads the locally-tracked `lidoLockedETH` mirror and
/// compares it against Lido's live stETH balance. Any dust sent directly
/// to this contract (or to Lido on its behalf) makes the live side exceed
/// the mirror, after which every deposit reverts and the contract is
/// effectively bricked.

interface IStETH {
    function balanceOf(address) external view returns (uint256);
    function submit(address) external payable returns (uint256);
}

contract LidoMirrorVuln {
    IStETH public immutable stETH;
    uint256 public lidoLockedETH;
    mapping(address => uint256) public shares;

    constructor(address _stETH) {
        stETH = IStETH(_stETH);
    }

    function deposit() external payable {
        // BUG: consistency gate on a mirror that can be desynced by any
        // attacker sending stETH directly. No reconciliation before use.
        uint256 live = stETH.balanceOf(address(this));
        require(live == lidoLockedETH, "desync");

        uint256 minted = stETH.submit{value: msg.value}(address(0));
        lidoLockedETH += minted;
        shares[msg.sender] += minted;
    }

    function redeem(uint256 amount) external {
        // Same mirror read, same DOS vector on withdrawal path.
        require(stETH.balanceOf(address(this)) == lidoLockedETH, "desync");
        shares[msg.sender] -= amount;
        lidoLockedETH -= amount;
    }
}
