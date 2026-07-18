pragma solidity ^0.8.20;

contract ReferralStorageClean {
    mapping(bytes32 => address) public codeOwners;
    mapping(address => bytes32) public accountCode;
    mapping(address => uint256) public referrerTiers;

    function registerCode(bytes32 _code) external {
        require(_code != bytes32(0), "ReferralStorage: invalid _code");
        require(accountCode[msg.sender] == bytes32(0), "ReferralStorage: account already has code");
        require(codeOwners[_code] == address(0), "ReferralStorage: code already exists");

        codeOwners[_code] = msg.sender;
        accountCode[msg.sender] = _code;
        referrerTiers[msg.sender] = 1;
    }
}
