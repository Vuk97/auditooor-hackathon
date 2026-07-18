pragma solidity ^0.8.20;

contract ReferralStorageVulnerable {
    mapping(bytes32 => address) public codeOwners;
    mapping(address => uint256) public referrerTiers;

    function registerCode(bytes32 _code) external {
        require(_code != bytes32(0), "ReferralStorage: invalid _code");
        require(codeOwners[_code] == address(0), "ReferralStorage: code already exists");

        codeOwners[_code] = msg.sender;
        referrerTiers[msg.sender] = 1;
    }
}
