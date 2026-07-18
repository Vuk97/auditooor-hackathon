// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

// Unbound-field case: _originDomain is DECLARED but omitted from the packed
// preimage -> a cross-origin replay seam. The detector must emit one needs-fuzz
// row for the unbound identity field _originDomain.
library MsgUnbound {
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
                _sender,
                _destinationDomain,
                _recipient,
                _messageBody
            );
    }
}
