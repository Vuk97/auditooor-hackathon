// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: delegated approval binds nonce, deadline, domain, salt, and
// consumes the authorization once.
contract ApprovalReplayDelegateSafe {
    mapping(address => mapping(address => uint256)) public delegationAmount;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public consumed;
    bytes32 public immutable domainSeparator;

    constructor() {
        domainSeparator = keccak256(abi.encode(block.chainid, address(this)));
    }

    function delegateApproval(
        address owner,
        address delegatee,
        uint256 amount,
        uint256 deadline,
        bytes32 salt,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "stale auth");
        uint256 nonce = nonces[owner];
        bytes32 digest = keccak256(
            abi.encode(
                owner,
                delegatee,
                amount,
                nonce,
                deadline,
                salt,
                domainSeparator
            )
        );
        require(!consumed[digest], "already used");
        require(_recover(digest, sig) == owner, "bad sig");
        consumed[digest] = true;
        nonces[owner] = nonce + 1;
        delegationAmount[owner][delegatee] = amount;
    }

    function _recover(bytes32 d, bytes calldata s) internal pure returns (address) {
        return address(uint160(uint256(d) ^ uint256(keccak256(s))));
    }
}
