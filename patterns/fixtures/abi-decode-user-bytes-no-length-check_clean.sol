// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AbiDecodeUserBytesNoLengthCheckClean {
    event Executed(address to, uint256 amount, bytes data);
    event Routed(uint256 kind, address target);

    // Minimum length for (address, uint256, bytes): 32 + 32 + 32 = 96 bytes
    // (offset for the dynamic bytes field, plus its length word).
    uint256 constant MIN_EXECUTE_LEN = 96;

    // CLEAN: length-checks the payload before abi.decode. Short payloads are
    // rejected with a clear revert reason rather than bubbling a decoder
    // revert out of a batched context.
    function execute(bytes calldata payload) external {
        require(payload.length >= MIN_EXECUTE_LEN, "short payload");
        (address to, uint256 amount, bytes memory data) =
            abi.decode(payload, (address, uint256, bytes));
        emit Executed(to, amount, data);
    }

    // CLEAN: inline require on length before abi.decode.
    function route(bytes calldata blob) external {
        require(blob.length == 64, "route: bad length");
        (uint256 kind, address target) = abi.decode(blob, (uint256, address));
        emit Routed(kind, target);
    }

    // CLEAN: length pre-check before touching the blob.
    function handleCallback(bytes memory cbData) external {
        require(cbData.length >= 32, "cb: too short");
        (uint256 x) = abi.decode(cbData, (uint256));
        emit Routed(x, address(0));
    }
}
