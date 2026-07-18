// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMessageDispatcher {
    function dispatch(bytes32 id, bytes calldata payload) external;
}

contract PendingStateExternalCallWithoutTerminalResetPositive {
    enum Status {
        None,
        Pending,
        Settled
    }

    struct PendingTx {
        address owner;
        uint256 amount;
        Status status;
    }

    mapping(bytes32 => PendingTx) public pending;
    IMessageDispatcher public dispatcher;

    constructor(IMessageDispatcher dispatcher_) {
        dispatcher = dispatcher_;
    }

    function startTransfer(bytes32 id, bytes calldata payload, uint256 amount) external {
        require(pending[id].status == Status.None, "already pending");
        pending[id].owner = msg.sender;
        pending[id].amount = amount;
        pending[id].status = Status.Pending;
        dispatcher.dispatch(id, payload);
    }
}
