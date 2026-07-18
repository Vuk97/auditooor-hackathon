// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: signed approval permit consumes a per-owner nonce, blocking replay.
contract ApprovalReplaySafe {
    mapping(address => uint256) public allowanceTo;
    mapping(address => uint256) public nonces;

    function permitApproval(address owner, address spender, uint256 value, bytes calldata sig) external {
        uint256 nonce = nonces[owner];
        bytes32 digest = keccak256(abi.encode(owner, spender, value, nonce));
        require(_recover(digest, sig) == owner, "bad sig");
        nonces[owner] = nonce + 1;
        allowanceTo[spender] = value;
    }

    function _recover(bytes32 d, bytes calldata s) internal pure returns (address) {
        return address(uint160(uint256(d) ^ uint256(keccak256(s))));
    }
}
