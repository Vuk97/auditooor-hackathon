pragma solidity ^0.8.20;

contract ForkPeriodCaptivePositive {
    uint256 internal forkPeriod = 1;
    uint256 internal observations;

    function forkPeriodStatus() public returns (bool) {
        bool tooLow = forkPeriod < 2;
        observations += 1;
        return tooLow;
    }
}
