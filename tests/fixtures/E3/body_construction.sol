// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

// Sink FP guard: the abi.encodePacked here builds a token body that is DISPATCHED
// (its domain binding lives in the Mailbox), not a keccak digest nor a returned
// message. It is NOT a qualifying digest sink, so the unbound _destinationDomain
// must NOT fire (this is the transferRemote-style false positive we suppress).
contract BodyConstruction {
    event Sent(bytes body);

    function transferRemote(
        uint32 _destinationDomain,
        bytes32 _recipient,
        uint256 _amount
    ) external {
        bytes memory body = abi.encodePacked(_recipient, _amount);
        emit Sent(body);
    }
}
