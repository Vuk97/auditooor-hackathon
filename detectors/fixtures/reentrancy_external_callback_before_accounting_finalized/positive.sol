// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IExitCallbackLift {
    function onExit(address account, uint256 amount, bytes calldata data) external;
}

interface IAssetLift {
    function safeTransfer(address to, uint256 amount) external;
}

contract ExternalCallbackBeforeAccountingFinalizedPositive {
    IAssetLift public asset;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public finalized;
    mapping(address => uint256) public exitCredit;

    function seed(address account, uint256 amount) external {
        balances[account] = amount;
    }

    function requestExit(
        bytes32 positionId,
        address callback,
        uint256 amount,
        bytes calldata data
    ) external {
        require(balances[msg.sender] >= amount, "balance");

        IExitCallbackLift(callback).onExit(msg.sender, amount, data);

        balances[msg.sender] -= amount;
        finalized[positionId] = true;
    }

    function settleExit(bytes32 positionId, uint256 amount) external {
        require(!finalized[positionId], "finalized");
        require(balances[msg.sender] >= amount, "balance");

        exitCredit[msg.sender] += amount;
        asset.safeTransfer(msg.sender, amount);
    }

    function ping(address callback, bytes calldata data) external {
        IExitCallbackLift(callback).onExit(msg.sender, 1, data);
    }
}
