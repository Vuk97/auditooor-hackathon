// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// COMPLETE-BINDING control: the leaf preimage commits the leafType discriminator,
// so a deposit leaf can never validate as a message leaf. E10 stays silent.
contract BridgeLeafComplete {
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
                    leafType,
                    originNetwork,
                    originAddress,
                    amount,
                    metadataHash
                )
            );
    }
}
