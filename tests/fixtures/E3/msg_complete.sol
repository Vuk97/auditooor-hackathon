// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

// Complete-binding control: the canonical message constructor binds every
// declared field (incl src+dst domain + nonce) into the packed preimage.
// Reachability finds all identity params bound -> clean (0 rows).
library MsgComplete {
    function formatMessage(
        uint8 _version,
        uint32 _nonce,
        uint32 _originDomain,
        bytes32 _sender,
        uint32 _destinationDomain,
        bytes32 _recipient,
        bytes calldata _messageBody
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                _version,
                _nonce,
                _originDomain,
                _sender,
                _destinationDomain,
                _recipient,
                _messageBody
            );
    }
}
