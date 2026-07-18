// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IExitCallbackCleanLift {
    function onExit(address account, uint256 amount, bytes calldata data) external;
}

interface IAssetCleanLift {
    function safeTransfer(address to, uint256 amount) external;
}

abstract contract ReentrancyGuardCleanLift {
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status != 2, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

contract FinalizeBeforeCallbackClean {
    IAssetCleanLift public asset;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public finalized;
    mapping(address => uint256) public exitCredit;

    function requestExit(
        bytes32 positionId,
        address callback,
        uint256 amount,
        bytes calldata data
    ) external {
        require(balances[msg.sender] >= amount, "balance");

        balances[msg.sender] -= amount;
        finalized[positionId] = true;

        IExitCallbackCleanLift(callback).onExit(msg.sender, amount, data);
    }

    function settleExit(bytes32 positionId, uint256 amount) external {
        require(!finalized[positionId], "finalized");
        require(balances[msg.sender] >= amount, "balance");

        exitCredit[msg.sender] += amount;
        asset.safeTransfer(msg.sender, amount);
    }
}

contract GuardedCallbackWithRevalidationClean is ReentrancyGuardCleanLift {
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public finalized;

    function requestExit(
        bytes32 positionId,
        address callback,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant {
        require(balances[msg.sender] >= amount, "balance");

        IExitCallbackCleanLift(callback).onExit(msg.sender, amount, data);

        require(balances[msg.sender] >= amount, "balance revalidated");
        balances[msg.sender] -= amount;
        finalized[positionId] = true;
    }

    function settleExit(bytes32 positionId, uint256 amount) external {
        require(!finalized[positionId], "finalized");
        require(balances[msg.sender] >= amount, "balance");
    }
}
