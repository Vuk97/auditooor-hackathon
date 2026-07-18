// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice VULNERABLE FIXTURE — intentionally incorrect test input for the
/// event-wrong-param-value detector. DO NOT DEPLOY.
///
/// The deposit function deducts a 1% fee and credits the net (post-fee)
/// amount to the user's balance, but emits the pre-fee `amount` in the
/// Deposit event. Off-chain indexers reconstructing balances from events
/// will diverge from on-chain state by the accumulated fee.
contract EventWrongParamVuln {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    // Event with the (likely wrong) amount-named arg as the first parameter,
    // which is exactly the shape the v1 regex-based detector targets.
    event Deposit(uint256 amount, address user);

    function deposit(uint256 amount) external {
        uint256 fee = amount / 100;         // fee adjustment present
        uint256 netAmount = amount - fee;   // net is what actually moves

        balances[msg.sender] += netAmount;
        totalSupply += netAmount;

        // VULN: emits gross `amount`, not `netAmount`, as the first arg.
        emit Deposit(amount, msg.sender);
    }
}
