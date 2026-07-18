// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IExitHookFire6 {
    function beforeFinalize(address account, bytes32 positionId, uint256 amount, bytes calldata data) external;
}

interface IAssetFire6 {
    function safeTransfer(address to, uint256 amount) external;
}

contract CallbackBeforeAccountingFinalizedCrossContractPositive {
    IAssetFire6 public asset;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public finalized;
    mapping(address => uint256) public exitCredits;

    function seed(address account, uint256 amount) external {
        balances[account] = amount;
    }

    function requestExit(
        bytes32 positionId,
        address hook,
        uint256 amount,
        bytes calldata data
    ) external {
        require(balances[msg.sender] >= amount, "balance");

        IExitHookFire6(hook).beforeFinalize(msg.sender, positionId, amount, data);

        balances[msg.sender] -= amount;
        finalized[positionId] = true;
    }

    function settleExit(bytes32 positionId, uint256 amount) external {
        require(!finalized[positionId], "finalized");
        require(balances[msg.sender] >= amount, "balance");

        exitCredits[msg.sender] += amount;
        asset.safeTransfer(msg.sender, amount);
    }
}
