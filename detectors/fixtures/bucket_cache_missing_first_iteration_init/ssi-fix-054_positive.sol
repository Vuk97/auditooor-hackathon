// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BucketCacheMissingFirstIterationInitPositive {
    mapping(address => mapping(uint256 => uint256)) public claimedBitmap;

    function claimRewards(uint256[] calldata rewardIds) external {
        uint256 cachedBucket;
        uint256 cachedBitmap;

        for (uint256 i = 0; i < rewardIds.length; ++i) {
            uint256 rewardBucket = rewardIds[i] / 256;
            uint256 rewardBit = 1 << (rewardIds[i] % 256);

            if (i == 0) {
                cachedBitmap = claimedBitmap[msg.sender][rewardBucket];
            } else if (cachedBucket != rewardBucket) {
                claimedBitmap[msg.sender][cachedBucket] = cachedBitmap;
                cachedBucket = rewardBucket;
                cachedBitmap = claimedBitmap[msg.sender][rewardBucket];
            }

            require(cachedBitmap & rewardBit == 0, "claimed");
            cachedBitmap |= rewardBit;
        }

        claimedBitmap[msg.sender][cachedBucket] = cachedBitmap;
    }
}
