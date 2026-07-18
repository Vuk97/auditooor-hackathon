// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMessageDispatcher {
    function dispatch(bytes32 id, bytes calldata payload) external;
}

contract PendingStateExternalCallWithoutTerminalResetClean {
    enum Status {
        None,
        Pending,
        Settled
    }

    struct PendingTx {
        address owner;
        uint256 amount;
        Status status;
        uint256 requestNonce;
        uint256 expiresAt;
    }

    mapping(bytes32 => PendingTx) public pending;
    IMessageDispatcher public dispatcher;
    uint256 public nextNonce = 1;

    constructor(IMessageDispatcher dispatcher_) {
        dispatcher = dispatcher_;
    }

    function startTransfer(bytes32 id, bytes calldata payload, uint256 amount) external {
        require(
            pending[id].status == Status.None || block.timestamp > pending[id].expiresAt,
            "already pending"
        );
        pending[id].owner = msg.sender;
        pending[id].amount = amount;
        pending[id].status = Status.Pending;
        pending[id].requestNonce = nextNonce++;
        pending[id].expiresAt = block.timestamp + 1 hours;
        try dispatcher.dispatch(id, payload) {
        } catch {
            pending[id].status = Status.None;
        }
    }
}
