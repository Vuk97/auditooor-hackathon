// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CLEAN FIXTURE — detector MUST NOT fire. The contract has a
/// canonical `minDelay` state var (so the precondition matches) but does
/// NOT expose any admin-gated bypass-shape function. The only mutating
/// entry point is the ordinary `queue` / `execute` pair that honors the
/// eta, whose names do not match the bypass regex.
contract TimelockImmediateExecuteClean {
    address public owner;
    uint256 public minDelay;

    struct Action {
        bytes32 id;
        uint256 eta;
        bool executed;
    }

    mapping(bytes32 => Action) public actions;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(uint256 _minDelay) {
        owner = msg.sender;
        minDelay = _minDelay;
    }

    function queue(bytes32 id) external onlyOwner {
        actions[id] = Action({id: id, eta: block.timestamp + minDelay, executed: false});
    }

    function execute(bytes32 id) external onlyOwner {
        Action storage a = actions[id];
        require(block.timestamp >= a.eta, "delay not elapsed");
        a.executed = true;
    }
}
