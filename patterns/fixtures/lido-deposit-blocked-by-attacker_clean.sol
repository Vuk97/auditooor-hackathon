// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. Same mirror variable
/// exists (so the contract-level precondition still holds), but every
/// deposit/redeem path calls `_syncLidoBalance()` before consuming the
/// mirror. Donated dust is absorbed into the mirror instead of bricking
/// the contract.

interface IStETH {
    function balanceOf(address) external view returns (uint256);
    function submit(address) external payable returns (uint256);
}

contract LidoMirrorClean {
    IStETH public immutable stETH;
    uint256 public lidoLockedETH;
    mapping(address => uint256) public shares;

    constructor(address _stETH) {
        stETH = IStETH(_stETH);
    }

    function _syncLidoBalance() internal {
        uint256 live = stETH.balanceOf(address(this));
        if (live > lidoLockedETH) {
            // Absorb donated dust into the mirror instead of reverting.
            lidoLockedETH = live;
        }
    }

    function deposit() external payable {
        _syncLidoBalance();
        uint256 minted = stETH.submit{value: msg.value}(address(0));
        lidoLockedETH += minted;
        shares[msg.sender] += minted;
    }

    function redeem(uint256 amount) external {
        _syncLidoBalance();
        shares[msg.sender] -= amount;
        lidoLockedETH -= amount;
    }
}
