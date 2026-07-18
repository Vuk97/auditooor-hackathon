// SPDX-License-Identifier: MIT
// Fixture: callback_reentrancy_no_guard — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

interface IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external returns (bytes4);
}

interface IERC1155 {
    function safeTransferFrom(address, address, uint256, uint256, bytes calldata) external;
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

contract CallbackReentrancyClean is IERC1155Receiver, ReentrancyGuard {
    uint256 public balance;
    IERC1155 public token;

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    // CLEAN fix #1: apply nonReentrant modifier
    function deposit(uint256 id, uint256 amount) external nonReentrant {
        token.safeTransferFrom(msg.sender, address(this), id, amount, "");
        balance += amount;
    }

    // CLEAN fix #2: CEI reordering (state write before external call)
    function depositCEI(uint256 id, uint256 amount) external {
        balance += amount;
        token.safeTransferFrom(msg.sender, address(this), id, amount, "");
    }
}
