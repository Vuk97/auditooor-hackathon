// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IExitHookFire6Clean {
    function beforeFinalize(address account, bytes32 positionId, uint256 amount, bytes calldata data) external;
}

interface IAssetFire6Clean {
    function safeTransfer(address to, uint256 amount) external;
}

contract CallbackBeforeAccountingFinalizedCrossContractClean {
    IAssetFire6Clean public asset;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public finalized;
    mapping(address => uint256) public exitCredits;
    mapping(address => uint256) public refunds;
    mapping(address => bool) public paid;

    bool private locked;

    modifier nonReentrant() {
        require(!locked, "locked");
        locked = true;
        _;
        locked = false;
    }

    function seed(address account, uint256 amount) external {
        balances[account] = amount;
        refunds[account] = amount;
    }

    function requestExitEffectsFirst(
        bytes32 positionId,
        address hook,
        uint256 amount,
        bytes calldata data
    ) external {
        require(balances[msg.sender] >= amount, "balance");

        balances[msg.sender] -= amount;
        finalized[positionId] = true;

        IExitHookFire6Clean(hook).beforeFinalize(msg.sender, positionId, amount, data);
    }

    function requestExitGuarded(
        bytes32 positionId,
        address hook,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant {
        require(balances[msg.sender] >= amount, "balance");

        IExitHookFire6Clean(hook).beforeFinalize(msg.sender, positionId, amount, data);

        balances[msg.sender] -= amount;
        finalized[positionId] = true;
    }

    function refundThenMarkPaid(address payable recipient, uint256 amount) external {
        require(refunds[msg.sender] >= amount, "refund");

        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "refund failed");

        refunds[msg.sender] -= amount;
        paid[msg.sender] = true;
    }

    function settleExit(bytes32 positionId, uint256 amount) external {
        require(finalized[positionId], "not finalized");
        require(balances[msg.sender] >= amount, "balance");

        exitCredits[msg.sender] += amount;
        asset.safeTransfer(msg.sender, amount);
    }

    receive() external payable {}
}
