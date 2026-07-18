// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: leafType is declared (the leaf IS usable under >1 class) but is NOT
// packed into the leaf preimage -> one forged proof validates as BOTH a deposit
// and a message leaf. E10 fires one needs-fuzz row on leafType (enum_by=name).
contract BridgeLeafUnbound {
    function getLeafValue(
        uint8 leafType,
        uint32 originNetwork,
        address originAddress,
        uint256 amount,
        bytes32 metadataHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    originNetwork,
                    originAddress,
                    amount,
                    metadataHash
                )
            );
    }
}
