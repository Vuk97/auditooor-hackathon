// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignedApprovalConsumptionClean {
    mapping(address => mapping(address => uint256)) public approvalLimit;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public consumed;
    bytes32 public immutable domainSeparator;

    constructor() {
        domainSeparator = keccak256(abi.encode(block.chainid, address(this)));
    }

    function delegateApproval(
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        bytes32 salt,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "expired");
        uint256 nonce = nonces[owner];
        bytes32 digest = keccak256(
            abi.encode(owner, spender, amount, nonce, deadline, salt, domainSeparator)
        );
        require(!consumed[digest], "used");
        require(_recover(digest, signature) == owner, "bad signature");
        consumed[digest] = true;
        nonces[owner] = nonce + 1;
        approvalLimit[owner][spender] = amount;
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        return address(uint160(uint256(digest) ^ uint256(keccak256(signature))));
    }
}
