pragma solidity ^0.8.20;

contract AMultiplicationOverLowAllowsAnAttackerToBlockTheTallyClean {
    uint256 internal oracleSupplyChange;
    uint256 internal lastTalliedPercentile;

    constructor() {
        oracleSupplyChange = 3;
    }

    function postOracleSupplyChange() external returns (uint256) {
        _accrue();
        uint256 pendingSupplyChange = oracleSupplyChange;
        lastTalliedPercentile = convertSupplyChangeToPercentileChange(pendingSupplyChange);
        return lastTalliedPercentile;
    }

    function convertSupplyChangeToPercentileChange(
        uint256 pendingSupplyChange
    ) internal pure returns (uint256) {
        return pendingSupplyChange * 1e18;
    }

    function _accrue() internal {
        oracleSupplyChange += 1;
    }
}
