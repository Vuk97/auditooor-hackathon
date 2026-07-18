// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BatchedEcrecoverReplayRiskPositive {
    mapping(address => bool) public validator;
    uint256 public threshold = 2;
    uint256 public totalExecuted;

    constructor(address first, address second) {
        validator[first] = true;
        validator[second] = true;
    }

    function executeBatch(bytes32 digest, bytes[] calldata signatures) external {
        uint256 approvals;

        for (uint256 i = 0; i < signatures.length; i++) {
            bytes calldata signature = signatures[i];
            require(signature.length == 65, "bad sig");

            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }

            address signer = ecrecover(digest, v, r, s);
            if (validator[signer]) {
                approvals += 1;
            }
        }

        require(approvals >= threshold, "below threshold");
        totalExecuted += 1;
    }
}
