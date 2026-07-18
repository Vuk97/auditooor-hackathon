// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VALUE-CREATION-SINK fixture for the dataflow-invariant-seed mutation test.
//   An attacker-controlled `amount` flows
//     payout(amount) -> _route(amt) -> _send(a) -> payable(to).transfer(a)
//   across >=2 internal call hops with NO require/assert bounding `amount`.
//   The recovered DefUsePath is unguarded:true into a value-moving sink.
//
//   The SINK function `_send` performs a mutable value-send
//   (`payable(to).transfer(a)`), so the mutation engine's `value_mutation`
//   operator can produce a VALUE-CREATION / value-change mutant
//   (`payable(to).transfer((a) / 2)`). A conservation harness over the flow
//   ("the sink moves exactly the source-authorized amount") MUST FAIL on that
//   mutant - that mutant kill is what proves the seeded conservation harness
//   non-vacuous.
contract ValueCreationSink {
    address public to;

    constructor(address _to) {
        to = _to;
    }

    // entrypoint: attacker chooses amount
    function payout(uint256 amount) external {
        _route(amount);
    }

    // hop 1
    function _route(uint256 amt) internal {
        _send(amt);
    }

    // hop 2 -> value-moving sink (mutable by value_mutation)
    function _send(uint256 a) internal {
        payable(to).transfer(a);
    }
}
