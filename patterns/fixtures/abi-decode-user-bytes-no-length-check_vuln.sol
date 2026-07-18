// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AbiDecodeUserBytesNoLengthCheckVuln {
    event Executed(address to, uint256 amount, bytes data);
    event Routed(uint256 kind, address target);

    // VULN: decodes caller-controlled bytes payload with no length pre-check.
    // A malformed (short) payload reverts inside abi.decode, DoS'ing any
    // multicall/relayer that batches this entry point.
    function execute(bytes calldata payload) external {
        (address to, uint256 amount, bytes memory data) =
            abi.decode(payload, (address, uint256, bytes));
        emit Executed(to, amount, data);
    }

    // VULN: also uses abi.decode on user bytes, different struct shape,
    // still no length validation.
    function route(bytes calldata blob) external {
        (uint256 kind, address target) = abi.decode(blob, (uint256, address));
        emit Routed(kind, target);
    }

    // VULN: abi.decodeWithSelector form, caller-controlled bytes parameter.
    function handleCallback(bytes memory cbData) external {
        bytes4 sel;
        assembly {
            sel := mload(add(cbData, 32))
        }
        bytes memory inner = new bytes(cbData.length - 4);
        for (uint256 i = 0; i < inner.length; i++) {
            inner[i] = cbData[i + 4];
        }
        (uint256 x) = abi.decode(inner, (uint256));
        emit Routed(x, address(0));
    }
}
