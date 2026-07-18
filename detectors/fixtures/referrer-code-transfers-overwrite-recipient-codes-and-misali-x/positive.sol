// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReferrerCodeTransfersOverwriteRecipientCodesAndMisaliXPositive {
    mapping(bytes32 => address) public codeOwners;
    mapping(address => bytes32) public codes;
    mapping(address => uint256) public referrerTiers;

    function setCodeOwner(bytes32 _code, address _newAccount) external {
        require(_code != bytes32(0), "invalid code");
        address account = codeOwners[_code];
        require(msg.sender == account, "not code owner");

        codeOwners[_code] = _newAccount;
        delete codes[account];
        codes[_newAccount] = _code;
    }
}
