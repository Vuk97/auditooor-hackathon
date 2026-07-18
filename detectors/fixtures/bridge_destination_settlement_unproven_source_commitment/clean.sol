pragma solidity ^0.8.20;

library MerkleProof {
    function verify(bytes32[] memory, bytes32, bytes32) internal pure returns (bool) {
        return true;
    }
}

contract BridgeDestinationSettlementClean {
    mapping(bytes32 => bool) public processedTransfers;
    mapping(address => uint256) public escrowCredit;
    bytes32 public sourceRoot;

    function finalizeBridgeERC20(
        address recipient,
        uint256 amount,
        bytes32 transferId,
        bytes32[] calldata proof
    ) external {
        bytes32 leaf = keccak256(abi.encode(recipient, amount, transferId));
        require(MerkleProof.verify(proof, sourceRoot, leaf), "bad source proof");
        require(!processedTransfers[transferId], "already finalized");
        processedTransfers[transferId] = true;

        escrowCredit[recipient] += amount;
    }
}
