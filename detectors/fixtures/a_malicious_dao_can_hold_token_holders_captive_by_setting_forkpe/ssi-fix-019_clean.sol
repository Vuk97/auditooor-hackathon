pragma solidity ^0.8.20;

contract ForkPeriodCaptiveClean {
    uint256 internal forkPeriod = 1;
    uint256 internal observations;

    function checkForkPeriod() internal view returns (bool) {
        return forkPeriod >= 2;
    }

    function forkPeriodStatus() public returns (bool) {
        bool withinBounds = checkForkPeriod();
        observations += 1;
        return withinBounds;
    }
}
