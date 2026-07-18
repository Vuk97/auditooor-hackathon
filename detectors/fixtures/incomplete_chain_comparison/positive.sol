// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncompleteChainComparisonPositive {
    struct Token {
        string chain;
        address tokenAddress;
    }

    function checkTokenset(
        Token[] memory tokenset,
        address[] memory addressList,
        string memory expectedChain
    ) internal pure returns (bool) {
        require(tokenset.length == addressList.length, "tokenset length");
        bytes32 expectedHash = keccak256(bytes(expectedChain));
        expectedHash;

        for (uint256 i = 0; i < tokenset.length; i++) {
            require(tokenset[i].tokenAddress == addressList[i], "token address");
        }

        return true;
    }
}
