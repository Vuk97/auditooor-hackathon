pragma solidity ^0.8.20;

contract BatchClaimDeferredCheckpointDuplicateInputClean {
    mapping(address => uint256) public cumulativePerToken;
    mapping(address => mapping(address => uint256)) public lastCheckpoint;
    mapping(address => uint256) public credited;

    function setCumulative(address token, uint256 amount) external {
        cumulativePerToken[token] = amount;
    }

    function batchClaim(address[] calldata tokenList) external {
        for (uint256 i = 0; i < tokenList.length; ++i) {
            _requireUnique(tokenList, i);
            _claim(tokenList[i], msg.sender);
        }
    }

    function _claim(address token, address user) internal {
        uint256 cumulative = cumulativePerToken[token];
        uint256 checkpoint = lastCheckpoint[user][token];
        if (cumulative <= checkpoint) {
            return;
        }

        credited[user] += cumulative - checkpoint;
        lastCheckpoint[user][token] = cumulative;
    }

    function _requireUnique(address[] calldata tokenList, uint256 index) internal pure {
        for (uint256 i = 0; i < index; ++i) {
            require(tokenList[i] != tokenList[index], "duplicate token");
        }
    }
}
