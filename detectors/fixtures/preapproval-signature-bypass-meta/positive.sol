pragma solidity ^0.8.20;

contract PreapprovalExchangePositive {
    mapping(bytes32 => bool) public preapproved;
    mapping(bytes32 => bool) public filled;

    function setPreapproved(bytes32 orderHash, bool allowed) external {
        preapproved[orderHash] = allowed;
    }

    function fill(bytes32 orderHash, bytes calldata signature) external {
        if (signature.length == 0) {
            require(preapproved[orderHash], "missing authorization");
        } else {
            require(signature.length == 65, "bad signature");
        }

        filled[orderHash] = true;
    }
}
