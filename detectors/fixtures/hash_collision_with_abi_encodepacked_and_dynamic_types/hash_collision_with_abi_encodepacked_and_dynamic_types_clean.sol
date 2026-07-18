pragma solidity ^0.8.20;

contract HashCollisionWithAbiEncodePackedDynamicTypesClean {
    function orderDigest(
        bytes32 makerSalt,
        bytes memory extraData
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(makerSalt, extraData));
    }
}
