// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecondSwapVestingVuln {
    mapping(uint256 => uint256) public stepsClaimed;
    struct Listing { uint256 vestingId; uint256 amount; address seller; }
    Listing[] public listings;
    function list(uint256 vestingId, uint256 amount) external returns (uint256 listingId) {
        listings.push(Listing(vestingId, amount, msg.sender));
        return listings.length - 1;
    }
    function claimable(uint256 listingId, uint256 currentStep) external view returns (uint256) {
        Listing storage l = listings[listingId];
        return (currentStep - stepsClaimed[l.vestingId]) * l.amount;
    }
}
