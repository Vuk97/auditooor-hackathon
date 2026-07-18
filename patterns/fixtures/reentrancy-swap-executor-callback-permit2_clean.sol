// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPermit2 { function permitTransferFrom(bytes calldata) external; }
interface ISwapExecutor { function executeSwap(bytes calldata) external; }

abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status != 2, "REENTRANT");
        _status = 2;
        _;
        _status = 1;
    }
}

contract ReentrancySwapExecutorCallbackPermit2Clean is ReentrancyGuard {
    IPermit2 public permit2;
    ISwapExecutor public SWAP_EXECUTOR;

    function swap(bytes calldata permitSig, bytes calldata swapData) external nonReentrant {
        permit2.permitTransferFrom(permitSig);
        SWAP_EXECUTOR.executeSwap(swapData);
    }
}
