// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract SigClean {
    address private _owner;

    function verifySignature(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view returns (bool) {
        require(_owner != address(0), "renounced");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "invalid sig");
        return signer == _owner;
    }
}
