// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract ERC2771MulticallVuln {
    address public trustedForwarder;
    address public owner;

    function _msgSender() internal view returns (address sender) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
        } else {
            sender = msg.sender;
        }
    }

    function transferOwnership(address newOwner) external {
        require(_msgSender() == owner, "not owner");
        owner = newOwner;
    }

    // VULN: public multicall with delegatecall and no guard
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "sub call failed");
            results[i] = ret;
        }
    }
}
