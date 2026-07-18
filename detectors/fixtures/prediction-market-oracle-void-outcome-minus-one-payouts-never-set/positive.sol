// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRealitio {
    function getResult(bytes32 questionId) external view returns (int256 outcome, bool finalized);
}

contract PredictionMarketOracleManagerPositive {
    enum MarketState {
        Open,
        Resolved
    }

    struct Market {
        int256 resolvedOutcome;
        MarketState state;
    }

    IRealitio public immutable oracle;
    mapping(uint256 => Market) public markets;
    mapping(uint256 => uint256[2]) public voidedPayouts;
    mapping(uint256 => bytes32) public questionIds;

    constructor(IRealitio oracle_) {
        oracle = oracle_;
    }

    function resolveMarket(uint256 marketId) external {
        (int256 outcome, bool finalized) = oracle.getResult(questionIds[marketId]);
        require(finalized, "not finalized");

        if (outcome == -1) {
            markets[marketId].resolvedOutcome = outcome;
            markets[marketId].state = MarketState.Resolved;
            return;
        }

        require(outcome == 0 || outcome == 1, "bad outcome");
        markets[marketId].resolvedOutcome = outcome;
        markets[marketId].state = MarketState.Resolved;
    }
}
