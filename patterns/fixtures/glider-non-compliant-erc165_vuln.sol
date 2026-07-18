// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract NftVuln {
    // VULN: supportsInterface does not return true for the ERC165 self-identification selector
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x80ac58cd; // ERC721 only
    }
}
