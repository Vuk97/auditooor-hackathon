// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecondSwapVestingClean {
    struct Listing { uint256 vestingId; uint256 amount; address seller; uint256 stepsClaimedAtListing; }
    Listing[] public listings;
    mapping(uint256 => uint256) public currentStep;
    function list(uint256 vestingId, uint256 amount) external returns (uint256 listingId) {
        listings.push(Listing(vestingId, amount, msg.sender, currentStep[vestingId]));
        return listings.length - 1;
    }
    function claimable(uint256 listingId) external view returns (uint256) {
        Listing storage l = listings[listingId];
        return (currentStep[l.vestingId] - l.stepsClaimedAtListing) * l.amount;
    }
}
