pragma solidity ^0.8.20;

contract ReferralRegistrySelfReferrerClean {
    mapping(address => address) internal referrerOf;
    event ReferralRegistered(address indexed trader, address indexed referrer);

    function registerReferral(address referrer) external {
        require(referrer != address(0), "missing referrer");
        require(referrer != msg.sender, "self referral blocked");
        require(referrerOf[msg.sender] == address(0), "already registered");

        referrerOf[msg.sender] = referrer;
        emit ReferralRegistered(msg.sender, referrer);
    }
}
