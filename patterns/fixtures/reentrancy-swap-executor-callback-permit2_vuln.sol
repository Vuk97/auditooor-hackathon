// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPermit2 { function permitTransferFrom(bytes calldata) external; }
interface ISwapExecutor { function executeSwap(bytes calldata) external; }

contract ReentrancySwapExecutorCallbackPermit2Vuln {
    IPermit2 public permit2;
    ISwapExecutor public SWAP_EXECUTOR;

    function swap(bytes calldata permitSig, bytes calldata swapData) external {
        // VULN: no nonReentrant. Executor can reenter and reuse the permit.
        permit2.permitTransferFrom(permitSig);
        SWAP_EXECUTOR.executeSwap(swapData);
    }
}
