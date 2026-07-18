pragma solidity ^0.8.20;

contract HashCollisionWithAbiEncodePackedDynamicTypesVulnerable {
    function orderDigest(
        string memory memo,
        bytes memory extraData
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(memo, extraData));
    }
}
