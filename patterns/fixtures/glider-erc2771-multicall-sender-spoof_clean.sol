// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ERC2771MulticallClean {
    address public trustedForwarder;
    address public owner;

    function _msgSender() internal view returns (address sender) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
        } else {
            sender = msg.sender;
        }
    }

    function isTrustedForwarder(address f) public view returns (bool) { return f == trustedForwarder; }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        // CLEAN: refuse multicall from trusted forwarder (strip spoof vector).
        require(!isTrustedForwarder(msg.sender), "no meta-multicall");
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "sub call failed");
            results[i] = ret;
        }
    }
}
