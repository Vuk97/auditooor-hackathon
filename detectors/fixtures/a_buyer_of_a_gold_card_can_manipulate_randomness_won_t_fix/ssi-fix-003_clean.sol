// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SkyweaverGoldCardRngDelayClean {
    uint256 internal mineGolds;
    uint256 internal rngDelay;
    uint256 internal recomitWindow;

    function seedGoldQueue(uint256 queuedGolds, uint256 delay) external {
        mineGolds = queuedGolds;
        rngDelay = delay;
    }

    function rngDelayForGoldCard(address buyer) external returns (bool) {
        refreshGoldCardRandomness(buyer);
        return mineGolds > recomitWindow;
    }

    function refreshGoldCardRandomness(address buyer) internal {
        recomitWindow = uint256(uint160(buyer)) % (rngDelay + 1);
    }
}
