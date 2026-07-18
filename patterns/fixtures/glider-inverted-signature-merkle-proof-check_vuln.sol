pragma solidity ^0.8.0;

library MerkleProof {
    function verify(bytes32[] memory, bytes32, bytes32) internal pure returns (bool) {
        return false;
    }
}

library ECDSA {
    function recover(bytes32, bytes memory) internal pure returns (address) {
        return address(0);
    }
}

contract AirdropVuln {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    function claim(bytes32[] calldata proof, uint256 amount, bytes memory signature) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        bytes32 digest = keccak256(abi.encodePacked(leaf));
        
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "bad sig");
        
        require(!MerkleProof.verify(proof, merkleRoot, leaf), "not in list");
        claimed[msg.sender] = true;
    }

    function verifyWithEcrecover(bytes32 hash, bytes memory sig) external pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}