// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally insecure test input for
/// the slashing-frontrun-withdrawal detector. DO NOT DEPLOY.
///
/// `slash` is admin-gated and correctly reduces the operator's active
/// balance, but it ignores `pendingWithdrawals`. A malicious operator
/// who observes the pending slash tx in the mempool can frontrun it
/// with `withdraw()`, shifting funds into the pending bucket and
/// escaping the penalty entirely.
contract SlasherVuln {
    address public owner;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => uint256) public withdrawReadyAt;

    uint256 public constant WITHDRAW_DELAY = 7 days;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function stake() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        pendingWithdrawals[msg.sender] += amount;
        withdrawReadyAt[msg.sender] = block.timestamp + WITHDRAW_DELAY;
    }

    function slash(address operator, uint256 amount) external onlyOwner {
        // Only touches the active balance. No retrospective haircut to
        // the pending-withdrawal bucket — victim can frontrun with
        // `withdraw` and fully escape the penalty.
        require(balances[operator] >= amount, "nothing to slash");
        balances[operator] -= amount;
    }

    function applySlash(address operator, uint256 amount) external onlyOwner {
        // Same shape on a second entry point.
        balances[operator] -= amount;
    }
}
