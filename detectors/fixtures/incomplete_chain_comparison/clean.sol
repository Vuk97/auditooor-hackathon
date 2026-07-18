// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IncompleteChainComparisonClean {
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

        for (uint256 i = 0; i < tokenset.length; i++) {
            require(tokenset[i].tokenAddress == addressList[i], "token address");
            require(
                keccak256(bytes(tokenset[i].chain)) == keccak256(bytes(expectedChain)),
                "token chain"
            );
        }

        return true;
    }
}
