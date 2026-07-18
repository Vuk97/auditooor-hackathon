// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// gasleft() threshold gate guarding a refund state transition.
contract Relayer {
    mapping(bytes32 => bool) public done;
    function execRefund(bytes32 id, address target, bytes calldata cd) external {
        require(gasleft() > 100000, "insufficient gas");  // <-- gasleft-threshold (refund)
        done[id] = true;
        (bool ok,) = target.call(cd);
        require(ok);
    }
}
