pragma solidity ^0.8.20;

interface ITellor {
    function getCurrentValue(bytes32 queryId)
        external
        view
        returns (bool ifRetrieve, uint256 value, uint256 timestampRetrieved);

    function getDataBefore(bytes32 queryId, uint256 timestamp)
        external
        view
        returns (bool ifRetrieve, uint256 value, uint256 timestampRetrieved);
}

contract BonqStyleBorrowLatestTellor {
    ITellor public immutable tellor;
    bytes32 public immutable queryId;
    mapping(address => uint256) public debt;

    constructor(ITellor tellor_, bytes32 queryId_) {
        tellor = tellor_;
        queryId = queryId_;
    }

    function borrowAgainstCollateral(uint256 collateralAmount, uint256 borrowAmount) external {
        (bool didGet, uint256 price, uint256 reportTimestamp) = tellor.getCurrentValue(queryId);
        require(didGet, "missing tellor value");

        uint256 collateralValue = collateralAmount * price / 1e18;
        require(reportTimestamp > 0, "timestamp required");
        require(collateralValue >= borrowAmount * 150 / 100, "insufficient collateral");

        debt[msg.sender] += borrowAmount;
    }
}
