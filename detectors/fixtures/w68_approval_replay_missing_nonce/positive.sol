// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: delegated approval can be replayed because the signed
// digest does not bind a freshness marker, deadline, domain separator, or
// consumed authorization marker.
contract ApprovalReplayDelegateVulnerable {
    mapping(address => mapping(address => uint256)) public delegationAmount;

    function delegateApproval(
        address owner,
        address delegatee,
        uint256 amount,
        bytes calldata sig
    ) external {
        bytes32 digest = keccak256(abi.encode(owner, delegatee, amount));
        require(_recover(digest, sig) == owner, "bad sig");
        delegationAmount[owner][delegatee] = amount;
    }

    function _recover(bytes32 d, bytes calldata s) internal pure returns (address) {
        return address(uint160(uint256(d) ^ uint256(keccak256(s))));
    }
}
