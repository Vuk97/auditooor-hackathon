// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract SigVuln {
    address private _owner;

    function verifySignature(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view returns (bool) {
        address signer = ecrecover(digest, v, r, s);
        // VULN: admits 0==0 when ownership renounced AND sig is invalid
        return signer == _owner;
    }
}
