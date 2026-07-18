// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossDomainMessengerClean {
    mapping(bytes32 => bool) public successfulMessages;
    function relayMessage(uint256 nonce, address source, address target, bytes calldata data) external returns (bool) {
        bytes32 messageHash = keccak256(abi.encode(nonce, source, target, data));
        require(!successfulMessages[messageHash], "replay");
        (bool ok, ) = target.call(data);
        if (ok) successfulMessages[messageHash] = true;
        return ok;
    }
}
