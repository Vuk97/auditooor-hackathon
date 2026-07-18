pragma solidity ^0.8.20;

contract PreapprovalExchangeClean {
    mapping(bytes32 => bool) public preapproved;
    mapping(bytes32 => bool) public filled;

    function setPreapproved(bytes32 orderHash, bool allowed) external {
        preapproved[orderHash] = allowed;
    }

    function fill(bytes32 orderHash, bytes calldata signature, uint256 deadline) external {
        require(block.timestamp <= deadline, "authorization expired");

        if (signature.length == 0) {
            require(preapproved[orderHash], "missing authorization");
        } else {
            require(signature.length == 65, "bad signature");
        }

        filled[orderHash] = true;
    }
}
