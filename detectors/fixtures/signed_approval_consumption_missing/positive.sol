// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignedApprovalConsumptionPositive {
    mapping(address => mapping(address => uint256)) public approvalLimit;

    function delegateApproval(
        address owner,
        address spender,
        uint256 amount,
        bytes calldata signature
    ) external {
        bytes32 digest = keccak256(abi.encode(owner, spender, amount));
        require(_recover(digest, signature) == owner, "bad signature");
        approvalLimit[owner][spender] = amount;
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        return address(uint160(uint256(digest) ^ uint256(keccak256(signature))));
    }
}
