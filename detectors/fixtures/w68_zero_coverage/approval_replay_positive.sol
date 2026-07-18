// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: signed approval permit replayed - no nonce consumed.
contract ApprovalReplayVulnerable {
    mapping(address => uint256) public allowanceTo;

    function permitApproval(address owner, address spender, uint256 value, bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encode(owner, spender, value));
        require(_recover(digest, sig) == owner, "bad sig");
        allowanceTo[spender] = value;
    }

    function _recover(bytes32 d, bytes calldata s) internal pure returns (address) {
        return address(uint160(uint256(d) ^ uint256(keccak256(s))));
    }
}
