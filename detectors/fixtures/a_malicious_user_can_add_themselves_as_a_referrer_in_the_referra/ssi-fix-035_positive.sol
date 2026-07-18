pragma solidity ^0.8.20;

contract ReferralRegistrySelfReferrerPositive {
    mapping(address => address) internal referrerOf;
    event ReferralRegistered(address indexed trader, address indexed referrer);

    function registerReferral(address referrer) external {
        require(referrer != address(0), "missing referrer");
        require(referrerOf[msg.sender] == address(0), "already registered");

        referrerOf[msg.sender] = msg.sender;
        emit ReferralRegistered(msg.sender, msg.sender);
    }
}
