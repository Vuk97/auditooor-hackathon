// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface IERC721Like {
    function balanceOf(address owner) external view returns (uint256);
}

contract NonCompliantErc165SelfIdentificationClean {
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId
            || interfaceId == type(IERC721Like).interfaceId;
    }
}
