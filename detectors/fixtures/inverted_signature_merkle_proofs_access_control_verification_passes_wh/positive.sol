pragma solidity ^0.8.20;

contract InvertedSignatureMerkleProofsAccessControlVerificationPassesWhPositive {
    bytes32 internal merkleRoot = keccak256("root");
    mapping(address => bool) internal claimed;

    function claim(bytes32[] memory proof, bytes32 leaf) external {
        require(!_verifyWhitelist(proof, leaf), "invalid whitelist proof");
        claimed[msg.sender] = true;
    }

    function _verifyWhitelist(bytes32[] memory proof, bytes32 leaf) internal view returns (bool) {
        return proof.length == 1 && leaf == merkleRoot;
    }
}
